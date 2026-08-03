use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, io::Write, path::PathBuf};

// scan a raw cookie value for embedded sensitive data; return tag list
fn url_decode(v:&str)->String{
    let mut out=String::with_capacity(v.len());
    let b=v.as_bytes(); let mut i=0;
    while i<b.len(){
        if b[i]==b'%' && i+2<b.len(){
            if let Ok(n)=u8::from_str_radix(&v[i+1..i+3],16){ out.push(n as char); i+=3; continue; }
        }
        out.push(b[i] as char); i+=1;
    }
    out
}

fn decodable(v:&str)->bool{
    use base64::Engine;
    let t=v.trim();
    if t.contains('%') { return true; }                       // url-encoded
    let parts:Vec<&str>=t.split('.').collect();
    if parts.len()==3 && parts.iter().all(|p|p.len()>4) { return true; } // JWT-shaped
    // base64 that yields >2 bytes and isn't just the same string
    for eng in [base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::URL_SAFE_NO_PAD]{
        if let Ok(b)=eng.decode(t.trim_end_matches('=')){ if b.len()>2 { return true; } }
    }
    // already-structured JSON is "decodable" in the sense of pretty-printable
    if t.starts_with('{') && t.contains(':') { return true; }
    false
}

fn detect_name(name:&str)->Vec<&'static str>{
    let n=name.to_lowercase();
    let mut t=vec![];
    if n.contains("geo")||n.contains("location")||n.contains("country")
       ||n.contains("region")||n.contains("_lat")||n.contains("_lon")
       ||n.contains("_city")||n.contains("timezone")||n.contains("_tz") { t.push("GEO-NAME"); }
    if n.contains("email")||n.contains("mail") { t.push("EMAIL-NAME"); }
    if n.contains("phone")||n.contains("mobile")||n.contains("_tel") { t.push("PHONE-NAME"); }
    if (n.contains("name")&&!n.contains("username")&&!n.contains("hostname")
        &&!n.contains("filename")) || n.contains("fullname")||n.contains("firstname") { t.push("NAME-NAME"); }
    if n=="uid"||n.contains("userid")||n.contains("_uid")||n.contains("deviceid")
       ||n.contains("device_id")||n.contains("visitorid") { t.push("DEVICE-ID"); }
    t
}

fn detect(v:&str)->String{
    let mut tags=vec![];
    // decode a URL-encoded layer so %40 -> @, %7B -> { etc. before scanning
    let decoded = if v.contains('%'){ url_decode(v) } else { v.to_string() };
    let v = &decoded[..];
    let t=v.trim();
    if t.len()<8 { return "-".into(); }                       // too short to hold IP/email/geo
    if matches!(t, "true"|"false"|"1"|"0"|"null"|"undefined") { return "-".into(); }
    if t.chars().all(|c|c.is_ascii_digit()) && t.len()<10 { return "-".into(); } // small int, not data
    // IPv4 — a real dotted quad, not 1.2.3.4-style version strings (require >=1 octet >=10)
    let re_ip = v.split(|c:char| !c.is_ascii_digit() && c!='.').any(|t|{
        let p:Vec<&str>=t.split('.').collect();
        p.len()==4 && p.iter().all(|o|o.parse::<u8>().is_ok())
            && p.iter().filter_map(|o|o.parse::<u16>().ok()).any(|n|n>10)
            && t.len()>=7
    });
    if re_ip { tags.push("IPv4"); }
    if v.matches("::").count()>=1 && v.split(':').filter(|h|h.len()>=2
        && h.chars().all(|c|c.is_ascii_hexdigit())).count()>=3 { tags.push("IPv6?"); }
    // email — user@domain.tld shape
    if let Some(at)=v.find('@'){
        let (u,rest)=v.split_at(at);
        if u.len()>=1 && rest.len()>=4 && rest.contains('.')
            && u.chars().last().map(|c|c.is_ascii_alphanumeric()).unwrap_or(false){ tags.push("EMAIL"); }
    }
    // lat,long pair
    if v.matches(|c:char|c==',').count()>=1 {
        let parts:Vec<&str>=v.split(',').collect();
        if parts.len()==2 && parts.iter().all(|p|p.trim().parse::<f64>().is_ok()){
            if let (Ok(a),Ok(b))=(parts[0].trim().parse::<f64>(),parts[1].trim().parse::<f64>()){
                if a.abs()<=90.0 && b.abs()<=180.0 && (a.fract()!=0.0||b.fract()!=0.0){tags.push("GEO?");}
            }
        }
    }
    // unix timestamp — a standalone 10-digit epoch token
    for tok in v.split(|c:char| !c.is_ascii_digit()){
        if tok.len()==10 && !tok.starts_with('0') {
            if let Ok(t)=tok.parse::<u64>(){ if t>1_600_000_000 && t<1_900_000_000 {tags.push("TIMESTAMP");break;} }
        }
    }
    // JSON / structured
    if (v.starts_with('{')&&v.contains(':')) || v.starts_with("%7B") { tags.push("JSON"); }
    // decoded-content keywords: real PII sitting inside a JSON/blob payload
    let lv=v.to_lowercase();
    if lv.contains("\"email\"")||lv.contains("email=")||lv.contains("@gmail")||lv.contains("@yahoo")
        ||lv.contains("@outlook")||lv.contains("@hotmail") { tags.push("EMAIL-PII"); }
    if lv.contains("\"name\"")||lv.contains("\"firstname\"")||lv.contains("\"fullname\"")
        ||lv.contains("username\"") { tags.push("NAME-PII"); }
    if lv.contains("\"phone\"")||lv.contains("\"mobile\"") { tags.push("PHONE-PII"); }
    if lv.contains("lat")&&lv.contains("lon")&&lv.contains(':') { tags.push("GEO-PII"); }
    // region codes like IN-TN, US-CA (ISO country-subdivision) — coarse location
    if t.len()>=4 && t.len()<=6 && t.contains('-') {
        let parts:Vec<&str>=t.split('-').collect();
        if parts.len()==2 && parts[0].len()==2 && parts[1].len()>=2 && parts[1].len()<=3
            && parts.iter().all(|p|p.chars().all(|c|c.is_ascii_uppercase())){ tags.push("GEO-REGION"); }
    }
    if lv.contains("country")||lv.contains("\"city\"")||lv.contains("region")||lv.contains("timezone"){ tags.push("GEO-HINT"); }
    if v.contains("%3A")||v.contains("%2F")||v.contains("%40") { tags.push("URL-ENC"); }
    // base64-ish blob — long, mixed-case, high-entropy encoded payload
    if v.len()>=24 && v.chars().all(|c|c.is_ascii_alphanumeric()||c=='+'||c=='/'||c=='='||c=='-'||c=='_')
        && v.chars().filter(|c|c.is_ascii_uppercase()).count()>=3
        && v.chars().filter(|c|c.is_ascii_lowercase()).count()>=3
        && v.chars().filter(|c|c.is_ascii_digit()).count()>=2 {
        tags.push("ENCODED-BLOB");
    }
    if tags.is_empty(){"-".into()}else{tags.join(",")}
}

fn load_trackers()->std::collections::HashMap<String,String>{
    let mut m=std::collections::HashMap::new();
    // DDG radar first (breadth), then local overrides on top (they win)
    for path in ["data/static/trackers.tsv","data/static/trackers_override.tsv"]{
        if let Ok(txt)=std::fs::read_to_string(path){
            for l in txt.lines(){
                if let Some((dom,owner))=l.split_once('\t'){
                    m.insert(dom.to_string(), owner.to_string());
                }
            }
        }
    }
    m
}

fn load_psl()->Option<publicsuffix::List>{
    use std::str::FromStr;
    // try vendored file first, then a couple of standard locations
    for path in ["data/static/public_suffix_list.dat",
                 "/usr/share/publicsuffix/public_suffix_list.dat"]{
        if let Ok(txt)=std::fs::read_to_string(path){
            if let Ok(list)=publicsuffix::List::from_str(&txt){ return Some(list); }
        }
    }
    None
}

fn entropy(v:&str)->f64{ if v.is_empty(){return 0.0;}
    let mut f=[0u32;256]; for &b in v.as_bytes(){f[b as usize]+=1;}
    let n=v.len() as f64;
    f.iter().filter(|&&c|c>0).map(|&c|{let p=c as f64/n;-p*p.log2()}).sum() }

fn etld1_psl(h:&str, psl:&Option<publicsuffix::List>)->String{
    use publicsuffix::Psl;
    let h=h.trim_start_matches('.');
    if let Some(list)=psl {
        if let Some(dom)=list.domain(h.as_bytes()){
            if let Ok(s)=std::str::from_utf8(dom.as_bytes()){ return s.to_string(); }
        }
    }
    // fallback: naive last-two-labels
    let p:Vec<&str>=h.rsplitn(3,'.').collect();
    if p.len()>=2 {format!("{}.{}",p[1],p[0])} else {h.into()}
}

// name -> (category, subtype). prefix-aware for mp_ / __Secure etc.
fn categorize(name:&str, cats:&HashMap<String,(String,String)>)->(String,String){
    if let Some(v)=cats.get(name){return v.clone();}
    for (k,v) in cats { if (k.ends_with('_')||k.starts_with("__")) && name.starts_with(k){return v.clone();} }
    // heuristic fallback by shape
    let n=name.to_lowercase();
    if n.contains("session")||n.contains("sess"){("Session".into(),"session".into())}
    else if n.contains("csrf")||n.contains("token")||n.contains("secure"){("Security".into(),"token".into())}
    else if n.contains("consent")||n.contains("gdpr"){("Consent".into(),"consent".into())}
    else if n.contains("lang")||n.contains("theme")||n.contains("tz"){("Preference".into(),"pref".into())}
    else {("Unknown".into(),"-".into())}
}

fn find_ff()->Vec<PathBuf>{ let home=std::env::var("HOME").unwrap_or_default();
    let mut o=vec![];
    for r in [".config/mozilla/firefox",".mozilla/firefox"]{
        let base=PathBuf::from(&home).join(r); if !base.exists(){continue;}
        for e in fs::read_dir(&base).into_iter().flatten().flatten(){
            let db=e.path().join("cookies.sqlite"); if db.exists(){o.push(db);} } }
    o }

pub fn run()->anyhow::Result<()>{
    fs::create_dir_all("data").ok();
    let psl=load_psl();
    let trackers=load_trackers();
    if psl.is_none(){ eprintln!("[panopticon] warning: PSL not found, using naive eTLD+1"); }
    let cats:HashMap<String,(String,String)> = fs::read_to_string("data/categories.txt")
        .unwrap_or_default().lines().filter_map(|l|{
            let p:Vec<&str>=l.split('\t').collect();
            if p.len()>=3 {Some((p[0].to_string(),(p[1].to_string(),p[2].to_string())))} else {None}
        }).collect();

    // pass 1: gather value hashes for sync detection
    let mut val_hosts:HashMap<String,std::collections::HashSet<String>>=HashMap::new();
    let mut val_meta:HashMap<String,(String,String)>=HashMap::new(); // hash -> (cookie_name, org)
    let mut val_preview:HashMap<String,String>=HashMap::new(); // hash -> full shared value
    let mut val_detail:HashMap<String,(String,f64)>=HashMap::new(); // hash -> (host, entropy)
    let mut rows:Vec<(String,String,String,i64,i32,f64,String,String,String,String)>=vec![]; // +value +detect +browser

    let mut raw:Vec<(String,String,String,i64,i32,String)>=vec![];
    for db in find_ff(){
        let uri=format!("file:{}?immutable=1",db.display());
        let conn=match Connection::open_with_flags(&uri,
            OpenFlags::SQLITE_OPEN_READ_ONLY|OpenFlags::SQLITE_OPEN_URI){Ok(c)=>c,Err(_)=>continue};
        let mut q=match conn.prepare(
            "SELECT host,name,value,expiry,sameSite FROM moz_cookies"){Ok(q)=>q,Err(_)=>continue};
        let it=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,
            r.get::<_,String>(2).unwrap_or_default(),r.get::<_,i64>(3).unwrap_or(0),
            r.get::<_,i32>(4).unwrap_or(-1)))).map(|x|x.filter_map(|y|y.ok()).collect::<Vec<_>>())
            .unwrap_or_default();
        raw.extend(it.into_iter().map(|(h,n,v,e,s)|(h,n,v,e,s,"firefox".to_string())));
    }
    // Chromium: decrypt cookie values in memory; same (host,name,value,expiry,samesite)
    // tuple shape as the Firefox reader plus the source browser, so the pass below
    // is source-agnostic but each row stays attributable.
    raw.extend(crate::chromium::read_all());

    // Cross-browser: the same (host,name) present in more than one browser. If the
    // values also match, the SAME identifier is following the user across browsers,
    // which is a stronger signal than a mere duplicate name.
    let mut hn_browsers:HashMap<(String,String),std::collections::HashSet<String>>=HashMap::new();
    let mut hn_values:HashMap<(String,String),std::collections::HashSet<String>>=HashMap::new();
    for (host,name,value,_,_,br) in &raw {
        let k=(host.clone(),name.clone());
        hn_browsers.entry(k.clone()).or_default().insert(br.clone());
        hn_values.entry(k).or_default().insert(value.clone());
    }

    for (host,name,value,exp,ss,browser) in raw {
        let e=entropy(&value);
        let vh=if value.len()>=10 && e>=3.0 {
            let mut h=Sha256::new(); h.update(value.as_bytes());
            let hh=format!("{:x}",h.finalize());
            val_hosts.entry(hh.clone()).or_default().insert(etld1_psl(&host, &psl));
            val_preview.entry(hh.clone()).or_insert_with(|| value.clone());
            val_detail.entry(hh.clone()).or_insert((host.clone(), e));
            let host_dom=etld1_psl(&host, &psl);
            let host_bare=host.trim_start_matches('.').to_string();
            let org = trackers.get(&host_bare)
                .or_else(||trackers.get(&host_dom))
                .cloned().unwrap_or_else(||{
                // fallback: cookie-name heuristic
                if name.starts_with("_cc_id")||name.starts_with("cto_")||name.starts_with("_pubcid"){"Criteo".into()}
                else if name.starts_with("unifiedid"){"TradeDesk".into()}
                else if name.starts_with("_ga")||name.starts_with("_gcl")||name=="NID"||name=="IDE"{"Google".into()}
                else if name.starts_with("_fbp")||name=="fr"{"Meta".into()}
                else if name.starts_with("MUID")||name.starts_with("_uet"){"Microsoft".into()}
                else {"unknown-broker".into()}
            });
            val_meta.entry(hh.clone()).or_insert_with(|| (name.clone(), org.clone()));
            hh
        } else {String::new()};
        // tab/newline would break the TSV — sanitize into the stored value
        let decoded_full = if value.contains('%'){ url_decode(&value) } else { value.clone() };
        let clean:String=decoded_full.chars().map(|c| if c=='\t'||c=='\n'||c=='\r'{' '}else{c}).collect();
        let mut det=detect(&value);
        let name_tags=detect_name(&name);
        if !name_tags.is_empty(){
            let extra=name_tags.join(",");
            det = if det=="-" { extra } else { format!("{det},{extra}") };
        }
        // cross-browser presence (see above): SAME-ID is the stronger finding.
        let k=(host.clone(),name.clone());
        if hn_browsers.get(&k).map(|s|s.len()>1).unwrap_or(false){
            let same=hn_values.get(&k).map(|s|s.len()==1).unwrap_or(false);
            let tag=if same {"XBROWSER-SAME-ID"} else {"XBROWSER"};
            det = if det=="-" { tag.to_string() } else { format!("{det},{tag}") };
        }
        rows.push((host.clone(),name,vh,exp,ss,e,etld1_psl(&host, &psl),clean,det,browser));
    }

    // which value-hashes are synced (>=2 distinct domains)
    let synced:std::collections::HashSet<&String> = val_hosts.iter()
        .filter(|(_,d)|d.len()>=2).map(|(h,_)|h).collect();

    // write enriched detail
    let mut out=fs::File::create("data/cookies_detail.tsv")?;
    writeln!(out,"host\tetld1\tname\tcategory\tsubtype\tentropy\texpiry\tsamesite\tsynced\tdetect\tvhash\tcandecode\tbrowser")?;
    for (host,name,vh,exp,ss,e,dom,value,det,browser) in &rows {
        let (cat,sub)=categorize(name,&cats);
        let ssn=match ss{0=>"none",1=>"lax",2=>"strict",_=>"?"};
        let persist=if *exp>0{"persistent"}else{"session"};
        let syncf=if !vh.is_empty() && synced.contains(vh){"SYNCED"}else{"-"};
        let vh12=if vh.len()>=12{&vh[..12]}else{"-"};
        let cd=if decodable(value){"Y"}else{"N"};
        writeln!(out,"{host}	{dom}	{name}	{cat}	{sub}	{e:.1}	{persist}	{ssn}	{syncf}	{det}	{vh12}	{cd}	{browser}")?;
    }
    // per-cookie partner lookup: this cookie's value-hash -> the OTHER domains sharing it
    // (written as host+name -> comma-domains so the TUI can show exact partners)
    // emit clusters: one line per synced value = the domains that share it
    let mut cl=fs::File::create("data/sync_clusters.tsv")?;
    for (h,doms) in &val_hosts {
        if doms.len()>=2 {
            let mut d:Vec<&String>=doms.iter().collect(); d.sort();
            let (cookie,org)=val_meta.get(h).cloned().unwrap_or(("?".into(),"?".into()));
            let prev=val_preview.get(h).cloned().unwrap_or("?".into())
                .replace('\t'," ").replace('\n'," ").replace('\r'," ");
            let (dhost,dent)=val_detail.get(h).cloned().unwrap_or(("?".into(),0.0));
            writeln!(cl,"{}\t{}\t{}\t{}\t{}\t{}\t{:.1}", &h[..12],
                d.iter().map(|x|x.as_str()).collect::<Vec<_>>().join(","), cookie, org, prev, dhost, dent)?;
        }
    }
    let mut pf=fs::File::create("data/sync_partners.tsv")?;
    for (h,doms) in &val_hosts {
        if doms.len()>=2 {
            let mut d:Vec<&String>=doms.iter().collect(); d.sort();
            writeln!(pf,"{}\t{}", &h[..12],
                d.iter().map(|x|x.as_str()).collect::<Vec<_>>().join(","))?;
        }
    }
    println!("enriched {} cookies -> data/cookies_detail.tsv",rows.len());
    println!("synced value-hashes: {}",synced.len());
    Ok(())
}
