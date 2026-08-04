use crossterm::{event::{self, Event, KeyCode, KeyModifiers}, terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}};
use ratatui::{prelude::*, widgets::*, text::Text};
use std::{collections::{HashMap, HashSet}, fs, io, time::Duration};

// ---------- data model ----------
#[derive(Clone)]
struct Cookie { host:String, dom:String, name:String, cat:String, sub:String,
                entropy:f64, expiry:String, samesite:String, synced:bool, same_owner:bool, detect:String, vhash:String, candecode:bool, browser:String, org:String, party:String }

// map a cookie name to the org that owns it (for tracker attribution)
fn cookie_org(name:&str)->Option<&'static str>{
    let n=name.to_lowercase();
    if n.starts_with("_ga")||n.starts_with("_gid")||n.starts_with("_gcl")||n=="ide"||n=="nid"||n=="consent"{Some("Google")}
    else if n.starts_with("_fbp")||n.starts_with("_fbc")||n=="fr"{Some("Meta")}
    else if n.starts_with("_uet")||n.starts_with("_clck")||n.starts_with("_clsk")||n=="muid"{Some("Microsoft")}
    else if n.starts_with("_cc_id")||n.starts_with("cto_")||n.starts_with("_pubcid"){Some("Criteo")}
    else if n.starts_with("unifiedid"){Some("TradeDesk")}
    else if n.starts_with("_pin"){Some("Pinterest")}
    else if n.starts_with("__qca"){Some("Quantcast")}
    else if n.starts_with("ajs_"){Some("Twilio")}
    else{None}
}

fn load()->Vec<Cookie>{
    fs::read_to_string("data/cookies_detail.tsv").unwrap_or_default().lines().skip(1)
        .filter_map(|l|{let f:Vec<&str>=l.split("	").collect();
            if f.len()<9{return None;}
            Some(Cookie{host:f[0].into(),dom:f[1].into(),name:f[2].into(),cat:f[3].into(),
                sub:f[4].into(),entropy:f[5].parse().unwrap_or(0.0),expiry:f[6].into(),
                samesite:f[7].into(),synced:f[8]=="SYNCED", same_owner:f[8]=="SAME-OWNER",
                detect:f.get(9).unwrap_or(&"-").to_string(),
                vhash:f.get(10).unwrap_or(&"-").to_string(),
                candecode:f.get(11).map(|x|*x=="Y").unwrap_or(false),
                browser:f.get(12).unwrap_or(&"firefox").to_string(),
                org:f.get(13).unwrap_or(&"-").to_string(),
                party:f.get(14).unwrap_or(&"-").to_string()})}).collect()
}

struct TrackerRow{ org:String, sites:usize, sync:usize, party:u8,
                   reach:u32, live:bool, topcat:String }

#[derive(Clone,Copy,PartialEq)]
enum Tab{Overview,Sites,Cookies,DataTypes,SyncGraph,Flows,Personal}
impl Tab{
    fn all()->[Tab;7]{[Tab::Overview,Tab::Sites,Tab::Cookies,Tab::DataTypes,Tab::SyncGraph,Tab::Flows,Tab::Personal]}
    fn title(&self)->&str{match self{Tab::Overview=>"Overview",Tab::Sites=>"Sites",
        Tab::Cookies=>"Cookies",Tab::DataTypes=>"Data Types",Tab::SyncGraph=>"Sync Graph",Tab::Flows=>"● Flows",Tab::Personal=>"⚠ Personal Data"}}
    fn idx(&self)->usize{Tab::all().iter().position(|t|t==self).unwrap()}
}


#[derive(Clone,Copy,PartialEq)]
enum ExportStage { None, Scope, Type, PiiRedact }

struct App{
    cookies:Vec<Cookie>, tab:Tab, sel:usize, expanded:bool,
    voff:usize,
    flows:std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<crate::wire::FlowEvent>>>,
    live_orgs:std::sync::Arc<std::sync::Mutex<std::collections::HashSet<String>>>,
    cookie_rx:std::sync::mpsc::Receiver<Vec<Cookie>>,
    last_scan:std::time::Instant,
    drill:Option<String>,
    decoded:std::collections::HashMap<String,Vec<(String,bool)>>,
    detail_scroll:u16,
    show_help:bool,
    help_scroll:u16,
    session_start:String,
    export:ExportStage,
    export_scope:String,
    export_type:String,
    export_msg:Option<String>,
    search:String,
    searching:bool,
    cat_filter:String,
    br_filter:String,
}

impl App{
    fn rows_len(&self)->usize{ match self.tab{
        Tab::Overview=>if let Some(o)=&self.drill {self.cookies_for_org(o).len()} else {self.trackers().len()},
        Tab::Sites=>if let Some(d)=&self.drill {self.cookies_for_site(d).len()} else {self.sites().len()},
        Tab::Cookies=>self.filtered_cookies().len(),
        Tab::DataTypes=>self.categories().len(),
        Tab::Flows=>self.flows.lock().unwrap().len(),
        Tab::Personal=>self.cookies.iter().filter(|c|is_pii(&c.detect)).count(),
        Tab::SyncGraph=>std::fs::read_to_string("data/sync_clusters.tsv")
            .unwrap_or_default().lines()
            .filter(|l|l.split("	").nth(1).map(|d|d.split(',').count()>=2).unwrap_or(false)).count(),
    }}

    fn filtered_cookies(&self)->Vec<&Cookie>{
        let q=self.search.to_lowercase();
        let pii_mode = self.cat_filter=="⚠ PII";
        let mut v:Vec<&Cookie>=self.cookies.iter()
            .filter(|c| self.cat_filter.is_empty()
                || (pii_mode && is_pii_val(&c.detect, &fetch_value(&c.host,&c.name,&c.browser)))
                || (!pii_mode && c.cat==self.cat_filter))
            .filter(|c| self.br_filter.is_empty() || c.browser==self.br_filter)
            .filter(|c| q.is_empty()
                || c.name.to_lowercase().contains(&q)
                || c.host.to_lowercase().contains(&q))
            .collect();
        v.sort_by(|a,b| b.entropy.partial_cmp(&a.entropy).unwrap());
        v
    }

    // ordered category list for the chip bar (fixed severity order + counts)
    fn pii_count(&self)->usize{
        self.cookies.iter()
            .filter(|c| is_pii_val(&c.detect, &fetch_value(&c.host,&c.name,&c.browser)))
            .count()
    }
    fn cat_chips(&self)->Vec<(String,usize)>{
        use std::collections::HashMap;
        let mut m:HashMap<String,usize>=HashMap::new();
        for c in &self.cookies {
            *m.entry(c.cat.clone()).or_default()+=1;
        }
        let order=["Advertising","Identifier","Behavior","Consent","Session","Security","Preference","Unknown"];
        let mut chips:Vec<(String,usize)>=order.iter()
            .filter_map(|c| m.get(*c).map(|n|(c.to_string(),*n))).collect();
        // any category not in the fixed order, appended
        for (k,v) in &m { if !order.contains(&k.as_str()) { chips.push((k.clone(),*v)); } }
        chips
    }

    fn trackers(&self)->Vec<TrackerRow>{
        use std::collections::{HashMap,HashSet};
        // Attribution comes from Tracker Radar via enrich (column `org`), falling back
        // to the cookie-name heuristic only where Radar has no entry. `third` marks an
        // org seen on at least one site it does not own — i.e. actually following you,
        // as opposed to a first-party site you visited.
        let mut m:HashMap<String,(HashSet<String>,usize,usize,HashMap<String,usize>,u8)>=HashMap::new();
        for c in &self.cookies{
            let org = if c.org!="-" && !c.org.is_empty() { Some(c.org.clone()) }
                      else { cookie_org(&c.name).map(|o|o.to_string()) };
            if let Some(org)=org{
                let e=m.entry(org).or_default();
                e.0.insert(c.dom.clone()); e.1+=1; if c.synced{e.2+=1;}
                *e.3.entry(c.cat.clone()).or_default()+=1;
                match c.party.as_str(){
                    "third"=>e.4=1,                       // definite: seen off its own sites
                    "first" if e.4==0 => e.4=2,           // only ever on its own sites
                    _=>{}                                 // unattributed: leave as unknown
                }
            }
        }
        // total distinct sites in the whole jar (denominator for reach%)
        let total_sites:HashSet<String>=self.cookies.iter().map(|c|c.dom.clone()).collect();
        let total=total_sites.len().max(1);
        let live=self.live_orgs.lock().unwrap();
        let mut v:Vec<TrackerRow>=m.into_iter().map(|(org,(sites,_cook,sync,cats,third))|{
            // top data category for this tracker
            let topcat=cats.iter().max_by_key(|(_,n)|**n).map(|(c,_)|c.clone()).unwrap_or("-".into());
            let is_live=live.contains(&org);
            let reach=(sites.len() as f64/total as f64*100.0) as u32;
            TrackerRow{ org, sites:sites.len(), sync, party:third, reach, live:is_live, topcat }
        }).collect();
        v.sort_by(|a,b|
            (b.party==1).cmp(&(a.party==1))
             .then((b.sync>0).cmp(&(a.sync>0)))
             .then(b.live.cmp(&a.live))
             .then(b.sites.cmp(&a.sites))
             .then(a.org.cmp(&b.org)));
        v
    }

    fn sites(&self)->Vec<(String,usize,usize,String)>{ // dom, #cookies, #trackers, top-cat
        let mut m:HashMap<String,(usize,HashSet<String>,HashMap<String,usize>)>=HashMap::new();
        for c in &self.cookies{
            let e=m.entry(c.dom.clone()).or_default();
            e.0+=1;
            if let Some(o)=cookie_org(&c.name){e.1.insert(o.into());}
            *e.2.entry(c.cat.clone()).or_default()+=1;
        }
        let q=self.search.to_lowercase();
        let mut v:Vec<_>=m.into_iter().map(|(d,(n,tr,cats))|{
            let top=cats.into_iter().max_by_key(|(c,n)|(*n,cat_severity(c))).map(|(c,_)|c).unwrap_or("-".into());
            (d,n,tr.len(),top)}).collect();
        if !q.is_empty(){ v.retain(|(d,_,_,_)| d.to_lowercase().contains(&q)); }
        v.sort_by(|a,b|
            b.2.cmp(&a.2)          // most trackers first
             .then(b.1.cmp(&a.1))  // then most cookies
             .then(a.0.cmp(&b.0))); // then A-Z
        v
    }

    fn categories(&self)->Vec<(String,usize,f64)>{ // cat, count, avg-entropy
        let mut m:HashMap<String,(usize,f64)>=HashMap::new();
        for c in &self.cookies{
            let e=m.entry(c.cat.clone()).or_default(); e.0+=1; e.1+=c.entropy; }
        let mut v:Vec<_>=m.into_iter().map(|(k,(n,es))|(k,n,es/n as f64)).collect();
        v.sort_by(|a,b|b.1.cmp(&a.1));
        v
    }

    fn current_site(&self)->Option<String>{
        if self.tab.idx()==Tab::Sites.idx() {
            self.sites().get(self.sel).map(|(d,_,_,_)|d.clone())
        } else { None }
    }
    fn cookies_for_site(&self, dom:&str)->Vec<&Cookie>{
        let mut v:Vec<&Cookie>=self.cookies.iter().filter(|c|c.dom==dom).collect();
        v.sort_by(|a,b| b.entropy.partial_cmp(&a.entropy).unwrap());
        v
    }
    fn cookies_for_org(&self, org:&str)->Vec<&Cookie>{
        let mut v:Vec<&Cookie>=self.cookies.iter()
            .filter(|c|cookie_org(&c.name)==Some(org)).collect();
        v.sort_by(|a,b| b.entropy.partial_cmp(&a.entropy).unwrap());
        v
    }
    fn selected_cookie(&self)->Option<Cookie>{
        if let Some(d)=&self.drill{
            let cs = if self.tab.idx()==Tab::Sites.idx() { self.cookies_for_site(d) }
                     else { self.cookies_for_org(d) };
            return cs.get(self.sel).map(|c|(*c).clone());
        }
        if self.tab.idx()==Tab::Cookies.idx(){
            self.filtered_cookies().get(self.sel).map(|c|(*c).clone())
        } else {None}
    }
}

fn cat_severity(cat:&str)->u8{ match cat{
    "Advertising"=>7,"Identifier"=>6,"Behavior"=>5,"Consent"=>4,
    "Session"=>3,"Security"=>2,"Preference"=>1,_=>0 }}

fn is_pii(detect:&str)->bool{
    // kept for the chip COUNT (tag presence); the value-aware check is is_pii_val
    let d=detect.to_uppercase();
    d.contains("PII")||d.contains("EMAIL")||d.contains("IPV4")||d.contains("IPV6")
    ||d.contains("GEO")||d.contains("PHONE")||d.contains("NAME")||d.contains("REGION")
    ||d.contains("DEVICE-ID")
}

fn trivial_val(v:&str)->bool{
    let t=v.trim();
    t.len()<3 || matches!(t,"true"|"false"|"1"|"0"|"null")
    || (t.chars().all(|c|c.is_ascii_digit()) && t.len()<=2)
}

// value-aware: a NAME-based tag only counts if the value is non-trivial;
// a value-based tag (…-PII, GEO-REGION, IPV4) always counts.
fn is_pii_val(detect:&str, value:&str)->bool{
    if !is_pii(detect) { return false; }
    let d=detect.to_uppercase();
    let value_based = d.contains("-PII")||d.contains("GEO-REGION")||d.contains("GEO-HINT")
        ||d.contains("IPV4")||d.contains("IPV6")||d.contains("EMAIL,")||d.contains(",EMAIL")||d=="EMAIL"
        ||d.contains("JSON");
    if value_based { return true; }
    // name-based only: require the value to actually carry something
    !trivial_val(value)
}

fn samesite_color(ss:&str)->Color{
    match ss {
        "none"   => Color::Red,
        "strict" => Color::Green,
        "lax"    => Color::Cyan,
        _        => Color::DarkGray,
    }
}

fn cat_color(cat:&str)->Color{ match cat{
    "Advertising"=>Color::Red, "Identifier"=>Color::LightRed, "Behavior"=>Color::Yellow,
    "Session"=>Color::Cyan, "Security"=>Color::Green, "Consent"=>Color::Magenta,
    "Preference"=>Color::Blue, _=>Color::DarkGray }}

fn window(sel:usize, voff:&mut usize, total:usize, height:usize)->usize{
    if height==0 {return 0;}
    if sel < *voff { *voff = sel; }
    else if sel >= *voff + height { *voff = sel + 1 - height; }
    if *voff + height > total { *voff = total.saturating_sub(height); }
    *voff
}

// Stable colour per browser so the source is readable at a glance.
fn browser_color(b:&str)->Color{
    match b {
        "firefox"=>Color::Rgb(255,149,0),
        "chrome"|"chrome-beta"|"chrome-dev"=>Color::Rgb(66,133,244),
        "chromium"=>Color::Rgb(120,170,255),
        "brave"|"brave-beta"=>Color::Rgb(251,84,43),
        "edge"|"edge-beta"|"edge-dev"=>Color::Rgb(0,173,239),
        "vivaldi"=>Color::Rgb(239,63,63),
        "opera"=>Color::Rgb(255,27,45),
        _=>Color::Gray,
    }
}

// Read a single cookie's value LIVE from the browser — never persisted to disk.
// `browser` is the row's source label, so a cookie that exists in several browsers
// resolves to the value from its OWN store rather than whichever matched first.
fn fetch_value(host:&str, name:&str, browser:&str)->String{
    use rusqlite::{Connection,OpenFlags};
    if browser.is_empty() || browser=="firefox" {
    let home=std::env::var("HOME").unwrap_or_default();
    for root in [".config/mozilla/firefox",".mozilla/firefox"]{
        let base=std::path::PathBuf::from(&home).join(root);
        if !base.exists(){continue;}
        for e in std::fs::read_dir(&base).into_iter().flatten().flatten(){
            let db=e.path().join("cookies.sqlite");
            if !db.exists(){continue;}
            let uri=format!("file:{}?immutable=1",db.display());
            if let Ok(conn)=Connection::open_with_flags(&uri,
                OpenFlags::SQLITE_OPEN_READ_ONLY|OpenFlags::SQLITE_OPEN_URI){
                if let Ok(v)=conn.query_row(
                    "SELECT value FROM moz_cookies WHERE host=?1 AND name=?2 LIMIT 1",
                    rusqlite::params![host,name], |r| r.get::<_,String>(0)){
                    return v;
                }
            }
        }
    }
    }
    // Chromium family (Chrome/Brave/Edge/…), decrypted live from the matching store.
    if browser!="firefox" {
        return crate::chromium::fetch_one(browser, host, name).unwrap_or_default();
    }
    String::new()
}

fn cookie_key(c:&Cookie)->String{
    format!("{}|{}",c.host,c.name)
}

fn deep_decode(v:&str)->Vec<(String,bool)>{
    // returns a trace: (line, is_success). Tries layers, peels recursively.
    use base64::Engine;
    use std::io::Read;
    let mut trace=vec![];
    let mut cur=v.to_string();
    let mut found_any=false;

    for pass in 1..=4 {
        let t=cur.trim().to_string();
        // 1) JWT
        let parts:Vec<&str>=t.split('.').collect();
        if parts.len()==3 && parts.iter().all(|p|p.len()>4){
            let dec=|x:&str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(x).ok()
                .and_then(|b|String::from_utf8(b).ok());
            if let (Some(h),Some(pl))=(dec(parts[0]),dec(parts[1])){
                trace.push((format!("pass {pass}: JWT ✓"),true));
                trace.push((format!("  header:  {h}"),true));
                trace.push((format!("  payload: {pl}"),true));
                return trace;
            }
        }
        // 2) url-encoded
        if t.contains('%'){
            let mut out=String::new(); let b=t.as_bytes(); let mut i=0;
            while i<b.len(){ if b[i]==b'%'&&i+2<b.len(){
                if let Ok(n)=u8::from_str_radix(&t[i+1..i+3],16){out.push(n as char);i+=3;continue;}}
                out.push(b[i] as char); i+=1; }
            if out!=t {
                trace.push((format!("pass {pass}: url-decode ✓"),true));
                found_any=true; cur=out; continue;
            }
        }
        // 3) base64 -> (maybe gzip) -> text
        let mut decoded_bytes=None;
        for eng in [base64::engine::general_purpose::STANDARD,
                    base64::engine::general_purpose::URL_SAFE_NO_PAD]{
            if let Ok(b)=eng.decode(t.trim_end_matches('=')){ if b.len()>2 { decoded_bytes=Some(b); break; } }
        }
        if let Some(bytes)=decoded_bytes {
            // gzip magic?
            if bytes.len()>2 && bytes[0]==0x1f && bytes[1]==0x8b {
                let mut gz=flate2::read::GzDecoder::new(&bytes[..]);
                let mut out=String::new();
                if gz.read_to_string(&mut out).is_ok() && !out.is_empty(){
                    trace.push((format!("pass {pass}: base64+gzip ✓"),true));
                    found_any=true; cur=out; continue;
                }
            }
            // zlib magic (0x78)?
            if bytes.len()>1 && bytes[0]==0x78 {
                let mut zl=flate2::read::ZlibDecoder::new(&bytes[..]);
                let mut out=String::new();
                if zl.read_to_string(&mut out).is_ok() && !out.is_empty(){
                    trace.push((format!("pass {pass}: base64+zlib ✓"),true));
                    found_any=true; cur=out; continue;
                }
            }
            // plain utf8?
            if let Ok(txt)=String::from_utf8(bytes.clone()){
                let printable=txt.chars().filter(|c|!c.is_control()).count();
                if printable as f64 > txt.len() as f64*0.8 && txt.len()>2 && txt!=t {
                    trace.push((format!("pass {pass}: base64 -> text ✓"),true));
                    found_any=true; cur=txt; continue;
                }
            }
            trace.push((format!("pass {pass}: base64 -> {} bytes binary (encrypted/opaque)",bytes.len()),false));
            break;
        }
        // nothing peeled this pass
        if !found_any { trace.push((format!("pass {pass}: no decodable layer"),false)); }
        break;
    }

    if found_any {
        trace.push(("─ fully decoded ─".into(),true));
        trace.push((cur,true));
        trace.push(("▪ DONE — fully unwrapped".into(),true));
        return trace;
    }
    // nothing peeled — say WHY, honestly
    let t=v.trim();
    let verdict = if t.starts_with('{') || t.starts_with('[') {
        "▪ already plaintext — this JSON IS the readable value, no wrapper to peel"
    } else if t.len()>=32 && t.chars().filter(|c|*c=='-').count()>=4
              && t.chars().all(|c|c.is_ascii_hexdigit()||c=='-') {
        "▪ random identifier (UUID) — no inner structure; the ID itself is the value"
    } else if trace.iter().any(|(l,_)|l.contains("binary")) {
        "▪ encrypted — decodes to binary; scrambled server-side, unreadable without their key"
    } else {
        "▪ opaque token — random/signed data, nothing encoded to unwrap"
    };
    trace.push((verdict.into(),false));
    trace
}

fn sync_partners(vhash:&str, self_dom:&str)->Vec<String>{
    if vhash=="-" {return vec![];}
    std::fs::read_to_string("data/sync_partners.tsv").unwrap_or_default().lines()
        .find_map(|l|{ let (h,doms)=l.split_once('\t')?;
            if h==vhash { Some(doms.split(',').filter(|d|*d!=self_dom)
                .map(|x|x.to_string()).collect()) } else {None} })
        .unwrap_or_default()
}

pub fn run()->anyhow::Result<()>{
    use std::sync::{Arc,Mutex};
    use std::collections::{VecDeque,HashSet};
    let mut cookies=load();
    // first run: if the metadata file doesn't exist yet, analyze cookies automatically
    if !std::path::Path::new("data/cookies_detail.tsv").exists() {
        eprintln!("[panopticon] first run — analyzing your cookies...");
        let _=std::process::Command::new(std::env::current_exe().unwrap_or_else(|_|"panopticon".into()))
            .arg("--enrich").status();
        cookies=load();  // reload after enrich
    }
    if cookies.is_empty(){
        eprintln!("[panopticon] no cookies found — is Firefox installed with a profile?");
        eprintln!("  (Panopticon reads ~/.config/mozilla/firefox or ~/.mozilla/firefox)");
        return Ok(());
    }

    let flows=Arc::new(Mutex::new(VecDeque::new()));
    let live_orgs=Arc::new(Mutex::new(HashSet::new()));

    // socket reader thread: pull FlowEvents from the P5 daemon
    {
        let (flows,live)=(flows.clone(),live_orgs.clone());
        std::thread::spawn(move ||{
            use std::io::{BufRead,BufReader};
            loop{
                let path=crate::wire::sock_path();
                match std::os::unix::net::UnixStream::connect(&path){
                    Ok(st)=>{
                        let rdr=BufReader::new(st);
                        for line in rdr.lines().map_while(Result::ok){
                            if let Ok(ev)=serde_json::from_str::<crate::wire::FlowEvent>(&line){
                                if let Some(o)=&ev.org { live.lock().unwrap().insert(o.clone()); }
                                let mut f=flows.lock().unwrap();
                                f.push_front(ev); if f.len()>200 {f.pop_back();}
                            }
                        }
                    }
                    Err(_)=>{ std::thread::sleep(std::time::Duration::from_secs(2)); }
                }
            }
        });
    }

    // cookie re-scan thread: re-run enrich + reload every 3s, push fresh set
    let (ctx,cookie_rx)=std::sync::mpsc::channel();
    std::thread::spawn(move ||{
        loop{
            std::thread::sleep(std::time::Duration::from_secs(3));
            // silently re-enrich (reads Firefox sqlite), then reload the tsv
            let _=std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--enrich").output();
            let fresh=load();
            if ctx.send(fresh).is_err(){break;}
        }
    });

    let mut app=App{cookies, tab:Tab::Overview, sel:0,
                    expanded:false, voff:0,
                    flows, live_orgs, cookie_rx, last_scan:std::time::Instant::now(), drill:None, decoded:std::collections::HashMap::new(), detail_scroll:0, show_help:false, help_scroll:0, session_start:chrono_now(), export:ExportStage::None, export_scope:String::new(), export_type:String::new(), export_msg:None, search:String::new(), searching:false, cat_filter:String::new(), br_filter:String::new()};

    enable_raw_mode()?;
    let mut out=io::stdout();
    crossterm::execute!(out, EnterAlternateScreen)?;
    let mut term=Terminal::new(CrosstermBackend::new(out))?;

    loop{
        // pull any freshly re-scanned cookie set
        while let Ok(fresh)=app.cookie_rx.try_recv(){
            if !fresh.is_empty(){ app.cookies=fresh; app.last_scan=std::time::Instant::now(); }
        }
        let app=&mut app;
        term.draw(|f|{
            let foot = if app.expanded && (app.tab.idx()==Tab::Cookies.idx() || app.drill.is_some()) {20} else {3};
            let z=Layout::vertical([Constraint::Length(3),Constraint::Min(6),
                Constraint::Length(foot)]).split(f.area());
            draw_tabs(f,z[0],&app);
            match app.tab{
                Tab::Overview=>draw_overview(f,z[1],app),
                Tab::Sites=>draw_sites(f,z[1],app),
                Tab::Cookies=>draw_cookies(f,z[1],app),
                Tab::DataTypes=>draw_datatypes(f,z[1],app),
                Tab::SyncGraph=>draw_sync(f,z[1],app),
                Tab::Flows=>draw_flows(f,z[1],app),
                Tab::Personal=>draw_personal(f,z[1],app),
            }
            if app.show_help { draw_help(f,z[1],app.help_scroll); }
            draw_export(f,z[1],app);
            draw_footer(f,z[2],app);
        })?;

        if event::poll(Duration::from_millis(150))?{
            if let Event::Key(k)=event::read()?{
                if app.show_help {
                    match k.code {
                        KeyCode::Down|KeyCode::Char('j') => { app.help_scroll=app.help_scroll.saturating_add(1); }
                        KeyCode::Up|KeyCode::Char('k')   => { app.help_scroll=app.help_scroll.saturating_sub(1); }
                        KeyCode::PageDown                => { app.help_scroll=app.help_scroll.saturating_add(15); }
                        KeyCode::PageUp                  => { app.help_scroll=app.help_scroll.saturating_sub(15); }
                        KeyCode::Home                    => { app.help_scroll=0; }
                        _ => { app.show_help=false; app.help_scroll=0; }
                    }
                    continue;
                }
                if matches!(k.code, KeyCode::Char('?')) { app.show_help=true; app.help_scroll=0; continue; }
                if app.export_msg.is_some() { app.export_msg=None; continue; }
                if app.export!=ExportStage::None {
                    let scope=app.export_scope.clone();
                    let rtype=app.export_type.clone();
                    match (app.export, k.code) {
                        (ExportStage::Scope, KeyCode::Char('c')) => {
                            app.export_scope = app.drill.clone().or_else(||app.current_site()).unwrap_or_else(||"all".into());
                            app.export=ExportStage::Type;
                        }
                        (ExportStage::Scope, KeyCode::Char('a')) => { app.export_scope="all".into(); app.export=ExportStage::Type; }
                        (ExportStage::Type, KeyCode::Char('1')) => {
                            let r=write_report(app,&scope,"audit",true);
                            app.export_msg=Some(match r{Ok(p)=>format!("✓ Saved full audit: {}",p),Err(e)=>format!("✗ {}",e)});
                            app.export=ExportStage::None;
                        }
                        (ExportStage::Type, KeyCode::Char('2')) => {
                            let r=write_report(app,&scope,"cookies",true);
                            app.export_msg=Some(match r{Ok(p)=>format!("✓ Saved cookie detail: {}",p),Err(e)=>format!("✗ {}",e)});
                            app.export=ExportStage::None;
                        }
                        (ExportStage::Type, KeyCode::Char('3')) => { app.export_type="pii".into(); app.export=ExportStage::PiiRedact; }
                        (ExportStage::PiiRedact, KeyCode::Char('s')) => {
                            let r=write_report(app,&scope,"pii",true);
                            app.export_msg=Some(match r{Ok(p)=>format!("✓ Saved personal-data (redacted): {}",p),Err(e)=>format!("✗ {}",e)});
                            app.export=ExportStage::None;
                        }
                        (ExportStage::PiiRedact, KeyCode::Char('f')) => {
                            let r=write_report(app,&scope,"pii",false);
                            app.export_msg=Some(match r{Ok(p)=>format!("✓ Saved personal-data (FULL, private): {}",p),Err(e)=>format!("✗ {}",e)});
                            app.export=ExportStage::None;
                        }
                        (_, KeyCode::Esc) => { app.export=ExportStage::None; }
                        _=>{ let _=(scope,rtype); }
                    }
                    continue;
                }
                if matches!(k.code, KeyCode::Char('e')) && !app.searching { app.export=ExportStage::Scope; continue; }
                // search-mode input capture (Sites & Cookies only)
                if app.searching {
                    let n=app.rows_len();
                    match k.code{
                        KeyCode::Esc=>{ app.searching=false; app.search.clear(); app.sel=0; app.voff=0; }
                        KeyCode::PageDown if app.expanded=>{ app.detail_scroll=app.detail_scroll.saturating_add(3); }
                    KeyCode::PageUp if app.expanded=>{ app.detail_scroll=app.detail_scroll.saturating_sub(3); }
                    KeyCode::Char('J') if app.expanded=>{ app.detail_scroll=app.detail_scroll.saturating_add(1); }
                    KeyCode::Char('K') if app.expanded=>{ app.detail_scroll=app.detail_scroll.saturating_sub(1); }
                    KeyCode::Enter=>{ app.searching=false; }  // keep filter, exit typing
                        KeyCode::Backspace=>{ app.search.pop(); app.sel=0; app.voff=0; }
                        KeyCode::Down=>{ if n>0 {app.sel=(app.sel+1).min(n-1);} }
                        KeyCode::Up=>{ if app.sel>0 {app.sel-=1;} }
                        KeyCode::Char(c)=>{ app.search.push(c); app.sel=0; app.voff=0; }
                        _=>{}
                    }
                    continue;
                }
                match k.code{
                    KeyCode::Esc if !app.search.is_empty()||!app.cat_filter.is_empty()||!app.br_filter.is_empty()=>{ app.search.clear(); app.searching=false; app.cat_filter.clear(); app.br_filter.clear(); app.sel=0; app.voff=0; }
                    KeyCode::Esc if app.expanded=>{ app.expanded=false; }
                    KeyCode::Esc if app.drill.is_some()=>{ app.drill=None; app.sel=0; app.voff=0; }
                    KeyCode::Backspace if app.drill.is_some()=>{ app.drill=None; app.sel=0; app.voff=0; app.expanded=false; }
                    KeyCode::Char('q')|KeyCode::Esc=>{ app.decoded.clear(); break; }
                    KeyCode::Tab=>{ let i=(app.tab.idx()+1)%7; app.tab=Tab::all()[i]; app.sel=0; app.expanded=false; app.drill=None; app.voff=0; app.search.clear(); app.searching=false; }
                    KeyCode::BackTab=>{ let i=(app.tab.idx()+6)%7; app.tab=Tab::all()[i]; app.sel=0; app.expanded=false; app.drill=None; app.voff=0; app.search.clear(); app.searching=false; }
                    KeyCode::Down|KeyCode::Char('j')=>{ let n=app.rows_len(); if n>0 {app.sel=(app.sel+1).min(n-1);} app.detail_scroll=0; }
                    KeyCode::Up|KeyCode::Char('k')=>{ if app.sel>0 {app.sel-=1;} app.detail_scroll=0; }
                    KeyCode::PageDown if app.expanded=>{ app.detail_scroll=app.detail_scroll.saturating_add(3); }
                    KeyCode::PageUp if app.expanded=>{ app.detail_scroll=app.detail_scroll.saturating_sub(3); }
                    KeyCode::Char('J') if app.expanded=>{ app.detail_scroll=app.detail_scroll.saturating_add(1); }
                    KeyCode::Char('K') if app.expanded=>{ app.detail_scroll=app.detail_scroll.saturating_sub(1); }
                    KeyCode::Enter=>{
                        if app.tab.idx()==Tab::SyncGraph.idx() {
                            app.expanded = !app.expanded;
                        } else if app.drill.is_some(){
                            app.expanded = !app.expanded;
                        } else {
                            match app.tab{
                                Tab::Sites=>{ let s=app.sites(); if let Some((dom,_,_,_))=s.get(app.sel){
                                    app.drill=Some(dom.clone()); app.sel=0; app.voff=0; app.expanded=false; } }
                                Tab::Overview=>{ let t=app.trackers(); if let Some(row)=t.get(app.sel){
                                    app.drill=Some(row.org.clone()); app.sel=0; app.voff=0; app.expanded=false; } }
                                _=>app.expanded = !app.expanded,
                            }
                        }
                    }
                    KeyCode::Left if matches!(app.tab,Tab::Cookies) && app.drill.is_none() =>{
                        let chips=app.cat_chips();
                        let mut names:Vec<String>=std::iter::once(String::new())
                            .chain(chips.iter().map(|(c,_)|c.clone())).collect();
                        if app.pii_count()>0 { names.insert(1,"⚠ PII".into()); }
                        let cur=names.iter().position(|c|c==&app.cat_filter).unwrap_or(0);
                        app.cat_filter=names[(cur+names.len()-1)%names.len()].clone();
                        app.sel=0; app.voff=0;
                    }
                    KeyCode::Right if matches!(app.tab,Tab::Cookies) && app.drill.is_none() =>{
                        let chips=app.cat_chips();
                        let mut names:Vec<String>=std::iter::once(String::new())
                            .chain(chips.iter().map(|(c,_)|c.clone())).collect();
                        if app.pii_count()>0 { names.insert(1,"⚠ PII".into()); }
                        let cur=names.iter().position(|c|c==&app.cat_filter).unwrap_or(0);
                        app.cat_filter=names[(cur+1)%names.len()].clone();
                        app.sel=0; app.voff=0;
                    }
                    KeyCode::Char('b') if matches!(app.tab,Tab::Cookies) && app.drill.is_none() && !app.searching =>{
                        // cycle: all browsers -> each browser present, in stable order
                        let mut names:Vec<String>=vec![String::new()];
                        let mut seen=std::collections::BTreeSet::new();
                        for c in &app.cookies { seen.insert(c.browser.clone()); }
                        names.extend(seen.into_iter());
                        let cur=names.iter().position(|c|c==&app.br_filter).unwrap_or(0);
                        app.br_filter=names[(cur+1)%names.len()].clone();
                        app.sel=0; app.voff=0;
                    }
                    KeyCode::Char('/') if matches!(app.tab,Tab::Sites|Tab::Cookies) && app.drill.is_none() =>{
                        app.searching=true; app.search.clear(); app.sel=0; app.voff=0;
                    }
                    KeyCode::Char('d')=>{
                        if let Some(c)=app.selected_cookie(){
                            if c.candecode {
                                let k=cookie_key(&c);
                                if !app.decoded.contains_key(&k){
                                    let live=fetch_value(&c.host,&c.name,&c.browser);
                                    let t=deep_decode(&live);
                                    app.decoded.insert(k,t);
                                }
                            }
                        }
                    }
                    _=>{}
                }
                if k.modifiers.contains(KeyModifiers::CONTROL)&&k.code==KeyCode::Char('c'){break;}
            }
        }
    }
    disable_raw_mode()?;
    crossterm::execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

fn draw_tabs(f:&mut Frame,a:Rect,app:&App){
    let titles:Vec<Line>=Tab::all().iter().map(|t|Line::from(t.title().to_string())).collect();
    let tabs=Tabs::new(titles).select(app.tab.idx())
        .block(Block::bordered().title(Line::from(vec![
            Span::styled(" PANOPTICON ",Style::new().bg(Color::Red).fg(Color::White).bold()),
            Span::raw(format!(" {} cookies ",app.cookies.len())),
            Span::styled(if app.flows.lock().unwrap().is_empty(){" ○ "}else{" ● LIVE "},
                Style::new().fg(if app.flows.lock().unwrap().is_empty(){Color::DarkGray}else{Color::Green}).bold()),
        ])))
        .highlight_style(Style::new().fg(Color::Black).bg(Color::Yellow).bold())
        .divider("│");
    f.render_widget(tabs,a);
}


fn search_box(app:&App)->Vec<Span<'static>>{
    if app.searching {
        vec![
            Span::styled(" search: ",Style::new().fg(Color::Black).bg(Color::Yellow).bold()),
            Span::styled(format!("{}_ ",app.search),Style::new().fg(Color::Black).bg(Color::Yellow).bold()),
        ]
    } else if !app.search.is_empty() {
        vec![
            Span::styled(format!(" filter: {} ",app.search),Style::new().fg(Color::Yellow).bold()),
            Span::styled("(/ edit, Esc clear) ",Style::new().fg(Color::DarkGray)),
        ]
    } else {
        vec![Span::styled(" / search ",Style::new().fg(Color::DarkGray))]
    }
}

fn draw_cookie_list(f:&mut Frame,a:Rect,app:&mut App,title:String,cs:Vec<Cookie>){
    let h=(a.height.saturating_sub(3)) as usize;
    let n=cs.len(); let sel=app.sel; let off=window(sel,&mut app.voff,n,h);
    let rows:Vec<Row>=cs.iter().enumerate().skip(off).take(h).map(|(i,c)|{
        let selr=i==app.sel; let col=cat_color(&c.cat);
        let sync=if c.synced{" ⇄"}else{""};
        let det=if c.detect!="-"{format!(" ⚠{}",c.detect)}else{String::new()};
        let seen=if app.decoded.contains_key(&cookie_key(c)){"✓ "}else{"  "};
        let ss_col=samesite_color(&c.samesite);
        let rowstyle=if selr{Style::new().fg(col).add_modifier(Modifier::REVERSED|Modifier::BOLD)}else{Style::new().fg(col)};
        let flags_cell=Cell::from(Line::from(vec![
            Span::styled(c.samesite.clone(),
                if selr{Style::new().fg(ss_col).add_modifier(Modifier::REVERSED|Modifier::BOLD)}
                else{Style::new().fg(ss_col)}),
            Span::styled(format!("{}{}",sync,det),
                if selr{Style::new().fg(Color::Red).add_modifier(Modifier::REVERSED)}
                else{Style::new().fg(Color::Red)}),
        ]));
        Row::new(vec![
            Cell::from(format!("{seen}{}",c.name)).style(rowstyle),
            Cell::from(c.cat.clone()).style(rowstyle),
            Cell::from(format!("{:.1}",c.entropy)).style(rowstyle),
            flags_cell,
        ])
    }).collect();
    f.render_widget(Table::new(rows,[Constraint::Min(26),Constraint::Length(12),
        Constraint::Length(8),Constraint::Min(24)])
        .header(Row::new(vec!["✓ COOKIE","CATEGORY","ENTROPY","FLAGS / DETECTED"])
            .style(Style::new().bold().fg(Color::Yellow)))
        .block(Block::bordered().title(format!("{title}  (✓ = decoded this session)"))), a);
}

fn draw_overview(f:&mut Frame,a:Rect,app:&mut App){
    if let Some(org)=app.drill.clone(){
        let cs:Vec<Cookie>=app.cookies_for_org(&org).into_iter().cloned().collect();
        let title=format!(" {} — {} cookies it set (Esc=back) ",org,cs.len());
        draw_cookie_list(f,a,app,title,cs);
        return;
    }
    let h=(a.height.saturating_sub(3)) as usize;
    let n=app.trackers().len();
    let sel=app.sel; let off=window(sel,&mut app.voff,n,h);
    let tr=app.trackers();
    let rows:Vec<Row>=tr.iter().enumerate().skip(off).take(h).map(|(i,t)|{
        let selr=i==app.sel;
        let base=Style::new().fg(if t.sync>0{Color::Red}else if t.sites>5{Color::LightRed}else{Color::Gray});
        let barw=(t.reach as usize*12/100).min(12);
        let bar=format!("{}{}", "█".repeat(barw), "░".repeat(12-barw));
        let livecell = if t.live {"● LIVE"} else {"· idle"};
        let livestyle = if t.live {Style::new().fg(Color::Red).bold()} else {Style::new().fg(Color::DarkGray)};
        let syncell = if t.sync>0 {format!("⇄ {}",t.sync)} else {"-".into()};
        let namestyle = if selr{base.add_modifier(Modifier::REVERSED|Modifier::BOLD)}else{base};
        Row::new(vec![
            Text::from(t.org.clone()).style(namestyle),
            Text::from(match t.party {1=>"third-party",2=>"first-party",_=>"unattributed"})
                .style(Style::new().fg(match t.party {1=>Color::Red,2=>Color::Green,_=>Color::DarkGray})),
            Text::from(format!("{}",t.sites)).style(base),
            Text::from(format!("{} {}%",bar,t.reach)).style(Style::new().fg(Color::Cyan)),
            Text::from(t.topcat.clone()).style(Style::new().fg(cat_color(&t.topcat))),
            Text::from(livecell.to_string()).style(livestyle),
            Text::from(syncell).style(base),
        ])
    }).collect();
    let confirmed=tr.iter().filter(|t|t.live).count();
    let tbl=Table::new(rows,[Constraint::Min(14),Constraint::Length(12),Constraint::Length(6),Constraint::Length(20),
        Constraint::Min(12),Constraint::Length(8),Constraint::Length(8)])
        .header(Row::new(vec!["COMPANY","RELATIONSHIP","SITES","REACH (% of browsing)","TOP DATA","STATUS","SYNC"])
            .style(Style::new().bold().fg(Color::Yellow)))
        .block(Block::bordered().title(
            format!(" who is tracking you ({}) — {} active now — Enter=its cookies ",tr.len(),confirmed)));
    f.render_widget(tbl,a);
}

fn draw_sites(f:&mut Frame,a:Rect,app:&mut App){
    if let Some(dom)=app.drill.clone(){
        let cs:Vec<Cookie>=app.cookies_for_site(&dom).into_iter().cloned().collect();
        let title=format!(" {} — {} cookies collected here (Esc=back) ",dom,cs.len());
        draw_cookie_list(f,a,app,title,cs);
        return;
    }
    let h=(a.height.saturating_sub(3)) as usize;
    let n=app.sites().len();
    let sel=app.sel; let off=window(sel,&mut app.voff,n,h);
    let s=app.sites();
    let rows:Vec<Row>=s.iter().enumerate().skip(off).take(h).map(|(i,(dom,cook,tr,top))|{
        let sel=i==app.sel;
        let col=if *tr>=3{Color::Red}else if *tr>0{Color::Yellow}else{Color::Gray};
        Row::new(vec![dom.clone(),format!("{cook}"),format!("{tr}"),top.clone()])
            .style(if sel{Style::new().fg(col).add_modifier(Modifier::REVERSED|Modifier::BOLD)}else{Style::new().fg(col)})
    }).collect();
    let t=Table::new(rows,[Constraint::Min(28),Constraint::Length(9),Constraint::Length(10),Constraint::Min(12)])
        .header(Row::new(vec!["SITE","COOKIES","TRACKERS","TOP CATEGORY"]).style(Style::new().bold().fg(Color::Yellow)))
        .block(Block::bordered()
            .title(format!(" sites collecting data ({}) — Enter=cookies ",s.len()))
            .title(Line::from(search_box(app)).right_aligned()));
    f.render_widget(t,a);
}

fn draw_cat_chips(f:&mut Frame,a:Rect,app:&App){
    let chips=app.cat_chips();
    let total:usize=chips.iter().map(|(_,n)|n).sum();
    let mut spans=vec![];
    // ⚠ PII chip first — the important one
    let pn=app.pii_count();
    if pn>0 {
        let pa = app.cat_filter=="⚠ PII";
        spans.push(Span::styled(format!(" ⚠ PII {pn} "),
            if pa {Style::new().fg(Color::White).bg(Color::Red).bold()}
            else {Style::new().fg(Color::Red).bold()}));
        spans.push(Span::raw("  "));
    }
    // "All" chip
    let all_active=app.cat_filter.is_empty();
    spans.push(Span::styled(format!(" All {} ",total),
        if all_active {Style::new().fg(Color::Black).bg(Color::White).bold()}
        else {Style::new().fg(Color::Gray)}));
    spans.push(Span::raw("  "));
    for (cat,n) in &chips {
        let active = &app.cat_filter==cat;
        let col=cat_color(cat);
        let st = if active {Style::new().fg(Color::Black).bg(col).bold()}
                 else {Style::new().fg(col)};
        spans.push(Span::styled(format!(" {cat} {n} "),st));
        spans.push(Span::raw(" "));
    }
    f.render_widget(Paragraph::new(Line::from(spans))
        .block(Block::bordered().title(" categories — ←/→ to filter ")), a);
}

fn draw_cookies(f:&mut Frame,a:Rect,app:&mut App){
    // split pane: chip bar (3 lines) on top, cookie table below
    let z=Layout::vertical([Constraint::Length(3),Constraint::Min(3)]).split(a);
    draw_cat_chips(f,z[0],app);
    let a=z[1];
    let h=(a.height.saturating_sub(3)) as usize;
    let n=app.filtered_cookies().len();
    let sel=app.sel; let off=window(sel,&mut app.voff,n,h);
    let cs=app.filtered_cookies();
    let rows:Vec<Row>=cs.iter().enumerate().skip(off).take(h).map(|(i,c)|{
        let sel=i==app.sel;
        let col=cat_color(&c.cat);
        let sync=if c.synced{" ⇄"}else{""};
        let ss_col=samesite_color(&c.samesite);
        let rowstyle=if sel{Style::new().fg(col).add_modifier(Modifier::REVERSED|Modifier::BOLD)}else{Style::new().fg(col)};
        let flags_cell=Cell::from(Line::from(vec![
            Span::styled(c.samesite.clone(),
                if sel{Style::new().fg(ss_col).add_modifier(Modifier::REVERSED|Modifier::BOLD)}
                else{Style::new().fg(ss_col)}),
            Span::styled(sync.to_string(),
                if sel{Style::new().fg(Color::Red).add_modifier(Modifier::REVERSED)}else{Style::new().fg(Color::Red)}),
        ]));
        Row::new(vec![
            Cell::from(c.name.clone()).style(rowstyle),
            Cell::from(c.cat.clone()).style(rowstyle),
            Cell::from(c.dom.clone()).style(rowstyle),
            Cell::from(c.browser.clone()).style(rowstyle.fg(browser_color(&c.browser))),
            Cell::from(format!("{:.1}",c.entropy)).style(rowstyle),
            flags_cell,
        ])
    }).collect();
    let t=Table::new(rows,[Constraint::Min(22),Constraint::Length(12),Constraint::Min(18),
        Constraint::Length(9),Constraint::Length(6),Constraint::Length(10)])
        .header(Row::new(vec!["COOKIE","CATEGORY","HOST","BROWSER","ENTROPY","FLAGS"]).style(Style::new().bold().fg(Color::Yellow)))
        .block(Block::bordered()
            .title(format!(" cookies ({}) — Enter=detail{} ",cs.len(),
                if app.br_filter.is_empty(){String::new()}else{format!(" — browser: {}",app.br_filter)}))
            .title(Line::from(search_box(app)).right_aligned()));
    f.render_widget(t,a);
}

fn draw_datatypes(f:&mut Frame,a:Rect,app:&mut App){
    let cats=app.categories();
    let max=cats.iter().map(|(_,n,_)|*n).max().unwrap_or(1);
    let rows:Vec<Row>=cats.iter().enumerate().map(|(i,(cat,n,ent))|{
        let sel=i==app.sel;
        let barw=(*n as f64/max as f64*30.0) as usize;
        let bar="█".repeat(barw);
        Row::new(vec![cat.clone(),format!("{n}"),format!("{:.1}",ent),bar])
            .style(if sel{Style::new().fg(cat_color(cat)).add_modifier(Modifier::REVERSED|Modifier::BOLD)}
                   else{Style::new().fg(cat_color(cat))})
    }).collect();
    let t=Table::new(rows,[Constraint::Min(14),Constraint::Length(8),Constraint::Length(10),Constraint::Min(30)])
        .header(Row::new(vec!["DATA TYPE","COUNT","AVG-ENTROPY","VOLUME"]).style(Style::new().bold().fg(Color::Yellow)))
        .block(Block::bordered().title(" what kind of data is collected — by volume "));
    f.render_widget(t,a);
}

fn draw_sync(f:&mut Frame,a:Rect,app:&mut App){
    struct Cluster{ doms:Vec<String>, cookie:String, org:String, preview:String, host:String, entropy:String }
    let mut clusters:Vec<Cluster> = std::fs::read_to_string("data/sync_clusters.tsv")
        .unwrap_or_default().lines().filter_map(|l|{
            let f:Vec<&str>=l.split("\t").collect();
            if f.len()<2 {return None;}
            let doms:Vec<String>=f[1].split(',').map(|s|s.to_string()).collect();
            if doms.len()<2 {return None;}
            Some(Cluster{ doms,
                cookie:f.get(2).unwrap_or(&"?").to_string(),
                org:f.get(3).unwrap_or(&"?").to_string(),
                preview:f.get(4).unwrap_or(&"?").to_string(),
                host:f.get(5).unwrap_or(&"?").to_string(),
                entropy:f.get(6).unwrap_or(&"?").to_string() })
        }).collect();
    clusters.sort_by(|a,b| b.doms.len().cmp(&a.doms.len())
        .then(a.doms.join(",").cmp(&b.doms.join(",")))
        .then(a.cookie.cmp(&b.cookie)));
    let org_color=|o:&str| match o {
        "Criteo"=>Color::Red,"TradeDesk"=>Color::LightRed,"Google"=>Color::Yellow,
        "Meta"=>Color::Blue,"Microsoft"=>Color::Cyan,_=>Color::Magenta };

    // DETAIL view: Enter on a cluster shows full breakdown
    if app.expanded {
        if let Some(cl)=clusters.get(app.sel){
            let oc=org_color(&cl.org);
            let (cat,_)=categorize_name(&cl.cookie);
            let mut lines=vec![
                Line::from(vec![
                    Span::styled(" ● ",Style::new().fg(oc).bold()),
                    Span::styled(format!("{} ",cl.org),Style::new().fg(oc).bold()),
                    Span::styled(format!("[{}] ",cl.cookie),Style::new().fg(Color::White)),
                    Span::styled(format!("· {}",cat),Style::new().fg(Color::DarkGray)),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled("  cookie:  ",Style::new().fg(Color::Yellow)),
                    Span::styled(cl.cookie.clone(),Style::new().fg(Color::White)),
                    Span::styled(format!("   set on {}",cl.host),Style::new().fg(Color::DarkGray))]),
                Line::from(vec![Span::styled("  category: ",Style::new().fg(Color::Yellow)),
                    Span::styled(format!("{}",cat),Style::new().fg(cat_color(cat))),
                    Span::styled(format!("   entropy {}",cl.entropy),Style::new().fg(Color::DarkGray))]),
                Line::from(vec![Span::styled("  broker:  ",Style::new().fg(Color::Yellow)),
                    Span::styled(cl.org.clone(),Style::new().fg(oc).bold())]),
                Line::from(""),
                Line::from(Span::styled("  SHARED VALUE (full):",Style::new().fg(Color::LightRed).bold())),
                Line::from(Span::styled(cl.preview.clone(),Style::new().fg(Color::White))),
                Line::from(""),
                Line::from(vec![Span::styled("  this exact value lives on all of these sites — ",Style::new().fg(Color::Gray)),
                    Span::styled(cl.org.clone(),Style::new().fg(oc).bold()),
                    Span::styled(" can join your activity across them:",Style::new().fg(Color::Gray))]),
                Line::from(""),
            ];
            for (j,d) in cl.doms.iter().enumerate(){
                let br=if j+1==cl.doms.len(){"      └──"}else{"      ├──"};
                lines.push(Line::from(vec![
                    Span::styled(br,Style::new().fg(oc)),
                    Span::styled(format!(" {}",d),Style::new().fg(Color::Cyan).bold()),
                    Span::styled(format!("  → feeds {}",cl.org),Style::new().fg(Color::DarkGray)),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("  Esc to go back",Style::new().fg(Color::DarkGray))));
            f.render_widget(Paragraph::new(lines).wrap(ratatui::widgets::Wrap{trim:false})
                .block(Block::bordered().title(" sync cluster detail ")),a);
            return;
        }
    }

    // LIST view: hub-and-spoke, one selectable line per cluster
    let mut lines=vec![
        Line::from(Span::styled("  broker sync — Enter a cluster to see the shared value + which sites feed it",
            Style::new().fg(Color::Magenta).bold())),
        Line::from(""),
    ];
    let h=(a.height.saturating_sub(4)) as usize;
    let per=5usize;
    let off=window(app.sel,&mut app.voff, clusters.len(), (h/per).max(1));
    for (i,cl) in clusters.iter().enumerate().skip(off).take((h/per).max(1)){
        let sel=i==app.sel; let oc=org_color(&cl.org);
        let (cat,_)=categorize_name(&cl.cookie);
        let hub=if sel{Style::new().fg(oc).add_modifier(Modifier::REVERSED|Modifier::BOLD)}else{Style::new().fg(oc).bold()};
        lines.push(Line::from(vec![
            Span::styled(if sel{"  ▶ ● "}else{"    ● "},hub),
            Span::styled(format!("{} ",cl.org),hub),
            Span::styled(format!("[{}] ",cl.cookie),Style::new().fg(Color::White)),
            Span::styled(format!("· {} ",cat),Style::new().fg(Color::DarkGray)),
            Span::styled(format!("= {}",
                {let v=&cl.preview; if v.len()>28{format!("{}…",&v[..28])}else{v.clone()}}),
                Style::new().fg(Color::Gray)),
        ]));
        for (j,d) in cl.doms.iter().enumerate(){
            let br=if j+1==cl.doms.len(){"      └──"}else{"      ├──"};
            lines.push(Line::from(vec![Span::styled(br,Style::new().fg(oc)),
                Span::styled(format!(" {}",d),Style::new().fg(Color::Cyan))]));
        }
        lines.push(Line::from(""));
    }
    if clusters.is_empty(){
        lines.push(Line::from(Span::styled("  (no client-visible syncs)",Style::new().fg(Color::DarkGray))));
    }
    f.render_widget(Paragraph::new(lines)
        .block(Block::bordered().title(format!(" sync graph — {} shared identifiers (↑↓ walk, Enter=detail) ",clusters.len()))),a);
}

// helper: cookie name -> (category, subtype) mirror of enrich, for the edge label
fn categorize_name(name:&str)->(&'static str,&'static str){
    let n=name.to_lowercase();
    if n.starts_with("_cc_id")||n.starts_with("cto_")||n.starts_with("_gcl")||n=="ide"||n=="nid"
       ||n.starts_with("_fbp")||n.starts_with("_uet")||n.starts_with("_pin")||n.starts_with("_scid")
       ||n.starts_with("_ttp")||n.starts_with("__qca"){ ("Advertising","ad-id") }
    else if n.starts_with("_ga")||n.starts_with("_pubcid")||n.starts_with("unifiedid")
       ||n=="muid"||n.starts_with("ajs_"){ ("Identifier","cross-site ID") }
    else if n.contains("consent"){ ("Consent","consent") }
    else { ("Identifier","shared value") }
}



fn draw_personal(f:&mut Frame,a:Rect,app:&mut App){
    use std::collections::BTreeMap;
    // bucket: type -> list of (site, cookie, decoded-snippet)
    let mut buckets:BTreeMap<&str,Vec<(String,String,String)>>=BTreeMap::new();
    for c in &app.cookies {
        if !is_pii(&c.detect){continue;}
        // (value-aware trivial recheck below, after we fetch the live value)
        let d=c.detect.to_uppercase();
        // decode the value once so email/name show readable, not %40
        let raw = fetch_value(&c.host,&c.name,&c.browser);
        if !is_pii_val(&c.detect,&raw){continue;}  // drop trivial-value name-flagged cookies
        let readable = if raw.contains('%'){
            let mut o=String::new(); let b=raw.as_bytes(); let mut i=0;
            while i<b.len(){ if b[i]==b'%'&&i+2<b.len(){
                if let Ok(n)=u8::from_str_radix(&raw[i+1..i+3],16){o.push(n as char);i+=3;continue;}}
                o.push(b[i] as char); i+=1; } o
        } else { raw.clone() };
        // pull the actual value out of JSON, not the first 60 chars of the blob
        let extract=|key:&str|->Option<String>{
            let pat=format!("\"{key}\":\"");
            readable.find(&pat).map(|i|{
                let start=i+pat.len();
                let rest=&readable[start..];
                let end=rest.find('"').unwrap_or(rest.len().min(80));
                rest[..end].to_string()
            })
        };
        let snip:String = readable.clone();  // full value; Paragraph wraps it
        let email=extract("email").or_else(||{
            // fallback: find an @-containing token
            readable.split(|c:char|c=='"'||c==','||c==' ').find(|t|t.contains('@')&&t.contains('.')).map(|s|s.to_string())
        });
        let name=extract("name");
        let mkpush=|k:&'static str, val:String, buckets:&mut BTreeMap<&str,Vec<(String,String,String)>>|
            buckets.entry(k).or_default().push((c.dom.clone(),c.name.clone(),val));
        let trivial = |v:&str|{ let t=v.trim();
            t.len()<3 || matches!(t,"true"|"false"|"1"|"0"|"null")
            || (t.chars().all(|c|c.is_ascii_digit()) && t.len()<=2) };

        // EMAIL: only if value actually contains an @ (name-flag alone isn't enough)
        if d.contains("EMAIL") {
            let ev = email.clone().unwrap_or(snip.clone());
            if ev.contains('@') { mkpush("Email addresses", ev, &mut buckets); }
        }
        // NAME-NAME (cookie literally named *name*) shouldn't dump the whole value as a "name"
        if d.contains("NAME-PII"){ if let Some(nm)=&name { if !trivial(nm){ mkpush("Names", nm.clone(), &mut buckets);} } }
        else if d.contains("NAME-NAME") && !trivial(&snip) { mkpush("Names", snip.clone(), &mut buckets); }
        if (d.contains("GEO")||d.contains("REGION")) && !trivial(&snip) { mkpush("Location", snip.clone(), &mut buckets); }
        if d.contains("PHONE"){ mkpush("Phone numbers", snip.clone(), &mut buckets); }
        if d.contains("IPV4")||d.contains("IPV6"){ mkpush("IP addresses", snip.clone(), &mut buckets); }
        if d.contains("DEVICE-ID") && !trivial(&snip) { mkpush("Device IDs", snip.clone(), &mut buckets); }
    }
    // severity order: identity first, then location, then network
    let order=["Email addresses","Names","Phone numbers","Location","IP addresses","Device IDs"];

    let mut lines=vec![
        Line::from(Span::styled("  personal data found in your cookies — decoded and readable",
            Style::new().fg(Color::Red).bold())),
        Line::from(Span::styled("  (this is your identity sitting in plaintext on these sites)",
            Style::new().fg(Color::DarkGray))),
        Line::from(""),
    ];
    let mut any=false;
    for key in order {
        if let Some(items)=buckets.get(key){
            any=true;
            lines.push(Line::from(vec![
                Span::styled(format!("  ▪ {} ",key),Style::new().fg(Color::Yellow).bold()),
                Span::styled(format!("({} found)",items.len()),Style::new().fg(Color::Red).bold()),
            ]));
            for (site,cookie,snip) in items.iter().take(12){
                lines.push(Line::from(vec![
                    Span::styled(format!("      {} ",site),Style::new().fg(Color::Cyan)),
                    Span::styled(format!("[{}] ",cookie),Style::new().fg(Color::DarkGray)),
                    Span::styled(snip.clone(),Style::new().fg(Color::White)),
                ]));
            }
            lines.push(Line::from(""));
        }
    }
    // live-flow PII: scan recent flow hosts/orgs (network side)
    let flows=app.flows.lock().unwrap();
    let flow_pii:Vec<String>=flows.iter()
        .filter(|e| e.host.contains('@') || e.host.matches('.').count()>=3
                    && e.host.split('.').take(4).all(|o|o.parse::<u8>().is_ok()))
        .map(|e| format!("{} → {}", e.comm, e.host)).collect();
    if !flow_pii.is_empty(){
        lines.push(Line::from(Span::styled("  ▪ Live network (PII-shaped destinations) ",
            Style::new().fg(Color::Yellow).bold())));
        for l in flow_pii.iter().take(6){
            lines.push(Line::from(Span::styled(format!("      {}",l),Style::new().fg(Color::Gray))));
        }
        any=true;
    }
    if !any {
        lines.push(Line::from(Span::styled("  no plaintext personal data detected in cookies (good — IDs are opaque)",
            Style::new().fg(Color::Green))));
    }
    // honest note: where device IDs and IPs actually live
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Note: device IDs (UUIDs) tracking you appear under Cookies as \"Identifier\" —",
        Style::new().fg(Color::DarkGray))));
    lines.push(Line::from(Span::styled(
        "  they're opaque but link your sessions. Your IP is logged server-side, keyed by",
        Style::new().fg(Color::DarkGray))));
    lines.push(Line::from(Span::styled(
        "  these cookie IDs, so it rarely appears in cookie values directly.",
        Style::new().fg(Color::DarkGray))));
    let off=window(app.sel,&mut app.voff, lines.len().saturating_sub(3), (a.height as usize).saturating_sub(3));
    let shown:Vec<Line>=lines.into_iter().skip(off).collect();
    f.render_widget(Paragraph::new(shown)
        .wrap(ratatui::widgets::Wrap{trim:false})
        .block(Block::bordered().title(" ⚠ Personal Data — your identity across sites ")), a);
}

fn draw_flows(f:&mut Frame,a:Rect,app:&mut App){
    let jar:std::collections::HashSet<String>=app.trackers().into_iter().map(|t|t.org).collect();
    let feed=app.flows.lock().unwrap();
    let live=app.live_orgs.lock().unwrap();
    let h=(a.height.saturating_sub(3)) as usize;
    let n=feed.len();
    let off=window(app.sel,&mut app.voff,n,h);
    let rows:Vec<Row>=feed.iter().enumerate().skip(off).take(h).map(|(_i,e)|{
        let is_tr=e.org.as_deref().map(|o|jar.contains(o)).unwrap_or(false);
        let col=if is_tr{Color::Red}else if e.org.is_some(){Color::Gray}else{Color::DarkGray};
        let host=if e.host!="?"{
            // a valid hostname is all ascii-alphanumeric / . / - ; anything else = reject to ?
            let valid = e.host.chars().all(|c| c.is_ascii_alphanumeric()||c=='.'||c=='-')
                && e.host.contains('.') && e.host.len()>=4
                && !e.host.contains("..");
            if valid { e.host.trim_end_matches('.').to_string() } else {"?".into()}
        }else{"?".into()};
        Row::new(vec![e.comm.clone(),format!("{}:{}",e.ip,e.port),host,
            e.org.clone().unwrap_or("-".into())]).style(Style::new().fg(col))
    }).collect();
    let title=format!(" live network egress — {} orgs active, {} flows (streaming) ",
        live.len(), feed.len());
    f.render_widget(Table::new(rows,[Constraint::Min(14),Constraint::Min(24),
        Constraint::Min(20),Constraint::Length(12)])
        .header(Row::new(vec!["PROCESS","DESTINATION","HOST","ORG"]).style(Style::new().bold().fg(Color::Yellow)))
        .block(Block::bordered().title(title)), a);
}

fn draw_help(f:&mut Frame,a:Rect,scroll:u16){
    let y=Color::Yellow; let g=Color::Gray; let w=Color::White; let dk=Color::DarkGray;
    let title=|t:&str| Line::from(Span::styled(t.to_string(),Style::new().fg(y).bold()));
    let body=|t:&str| Line::from(Span::styled(format!("     {t}"),Style::new().fg(g)));
    let item=|k:&str,v:&str| Line::from(vec![
        Span::styled(format!("  {:13}",k),Style::new().fg(w).bold()),
        Span::styled(v.to_string(),Style::new().fg(g))]);
    // pad to a column, but never let a long label butt up against its description
    let flag=|k:&str,col:Color,v:&str| Line::from(vec![
        Span::styled(format!("  {:8} ",k),Style::new().fg(col).bold()),
        Span::styled(v.to_string(),Style::new().fg(g))]);
    let blank=||Line::from("");
    let lines=vec![
        Line::from(Span::styled("PANOPTICON — what everything means",Style::new().fg(Color::Red).bold())),
        Line::from(Span::styled("This tool shows what websites store about you and who they send it to. Press any key to close.",Style::new().fg(dk))),
        blank(),

        title("WHAT IS A COOKIE?"),
        body("A small file a website saves in your browser. Some remember your login (useful);"),
        body("others are secret ID tags that let companies follow you around the web (tracking)."),
        blank(),

        title("COOKIE CATEGORIES — what each cookie is doing"),
        item("Advertising","Used by ad companies to track what you look at and target ads at you."),
        item("Identifier","A unique tag that singles you out — like a fingerprint for your browser."),
        item("Behavior","Records how you use a site: what you click, how long you stay, where you scroll."),
        item("Session","Keeps you logged in / remembers your cart. Usually necessary and harmless."),
        item("Security","Protects the site (bot checks, fraud prevention). Normal and expected."),
        item("Consent","Stores your cookie-banner choices (accept/reject)."),
        item("Preference","Remembers settings like language, dark mode, region."),
        item("Unknown","Purpose unclear — could be anything; worth a closer look."),
        blank(),

        title("ENTROPY — is this cookie a tracking ID?"),
        body("Measures how random a value is. Random = a unique tag pointing at YOU."),
        flag(">4.0",Color::Red,"high — identifier-grade. This almost certainly tracks you."),
        flag("3-4",g,"moderate — might be an ID."),
        flag("<3",dk,"low — probably just a setting, not an ID."),
        blank(),

        title("SAMESITE — can this cookie follow you to OTHER sites?"),
        flag("none",Color::Red,"YES — sent everywhere, including on other websites. Enables tracking."),
        flag("strict",Color::Green,"NO — only works on the site that made it. Safest."),
        flag("lax",Color::Cyan,"Mostly no — the normal default."),
        flag("?",dk,"The cookie didn't say (browser treats it as 'lax')."),
        blank(),

        title("BROWSER — which browser this cookie came from"),
        body("The same site can store different cookies in each browser you use."),
        flag("XBROWSER",Color::Yellow,"this cookie name exists in more than one of your browsers."),
        flag("XBROWSER-SAME-ID",Color::Red,"the SAME value is in several browsers — one identifier follows you across all of them."),
        blank(),

        title("SYNC  (⇄ symbol)"),
        body("The SAME ID value was found on several different websites. Whoever set it can"),
        body("tell those visits belong to one person — that is what makes it worth showing."),
        body("It is strong evidence, not proof of a deal: sometimes an ad broker is linking"),
        body("sites deliberately, sometimes one company simply uses one cookie across its own"),
        body("properties. When Panopticon can tell the domains share an owner it says"),
        body("\"same owner\" instead, and only unrelated parties are flagged red."),
        blank(),

        title("PERSONAL DATA (PII) — your actual identity in a cookie"),
        body("When a cookie contains real info about you, not just a random tag:"),
        body("Email · Name · Location · Phone · IP address · Device ID. Shown decoded & readable."),
        blank(),

        title("COMPANY / RELATIONSHIP — who is this, and are they following you?"),
        body("first-party  a company on its own websites. Wikipedia setting a cookie on"),
        body("             wikipedia.org is normal and not tracking across the web."),
        body("third-party  present on sites it does NOT own — an ad or analytics company"),
        body("             riding along on someone else's page. These are listed first."),
        blank(),

        title("FLOWS — live internet connections leaving your computer"),
        item("ORG","The company that owns the server you're connecting to (Google, Cloudflare…)."),
        item("HOST","The server's name, if we can find it. '?' means the name is hidden/unpublished,"),
        body("       but the ORG still tells you who owns it."),
        blank(),

        title("DECODE  (press d)"),
        body("Some cookie values are scrambled (base64/JWT/gzip). Decode unscrambles them to"),
        body("reveal what's really inside. ✓ marks cookies you've already decoded this session."),
        blank(),

        title("A FEW TECH TERMS"),
        item("eTLD+1","The real website name. e.g. 'shop.example.co.uk' belongs to 'example.co.uk'."),
        item("ASN","A block of internet addresses owned by one company — how we name the ORG."),
        item("broker","A company whose business is tracking you across many sites and selling profiles."),
        blank(),

        title("KEYS"),
        item("Tab","move between the tabs at the top"),
        item("↑ ↓","move up/down a list       Enter  open details / drill in"),
        item("Esc","go back / close            /      search"),
        item("← →","filter by category (Cookies tab)"),
        item("b","filter by browser (Cookies tab) — cycles firefox / chrome / brave / …"),
        item("d","decode the selected cookie  ?  this help   q  quit"),
        item("PgUp/PgDn","scroll inside a long cookie detail (Fn+↑/↓ on laptops)"),
    ];
    f.render_widget(Clear,a);
    // clamp so paging past the end doesn't leave a blank pane
    let max=(lines.len() as u16).saturating_sub(a.height.saturating_sub(2)).max(0);
    let scroll=scroll.min(max);
    f.render_widget(Paragraph::new(lines)
        .scroll((scroll,0))
        .wrap(ratatui::widgets::Wrap{trim:false})
        .block(Block::bordered()
            .border_style(Style::new().fg(Color::Yellow))
            .title(" ? HELP — ↑/↓ PgUp/PgDn to scroll · any other key closes ")), a);
}


fn md_table(headers:&[&str], rows:&[Vec<String>])->String{
    let ncol=headers.len();
    // compute max width per column (header vs all cells)
    let mut w=vec![0usize;ncol];
    for (i,h) in headers.iter().enumerate(){ w[i]=h.chars().count(); }
    for r in rows { for (i,c) in r.iter().enumerate().take(ncol){
        w[i]=w[i].max(c.chars().count());
    }}
    let pad=|s:&str,width:usize|{
        let len=s.chars().count();
        format!("{}{}",s," ".repeat(width.saturating_sub(len)))
    };
    let mut o=String::new();
    // header row
    o.push_str("| ");
    o.push_str(&headers.iter().enumerate().map(|(i,h)|pad(h,w[i])).collect::<Vec<_>>().join(" | "));
    o.push_str(" |
");
    // separator row (dashes sized to each column)
    o.push_str("|");
    for width in &w { o.push_str(&format!("-{}-|","-".repeat(*width))); }
    o.push('\n');
    // data rows
    for r in rows {
        o.push_str("| ");
        let cells:Vec<String>=(0..ncol).map(|i|{
            let c=r.get(i).map(|x|x.as_str()).unwrap_or("");
            pad(c,w[i])
        }).collect();
        o.push_str(&cells.join(" | "));
        o.push_str(" |
");
    }
    o
}

fn pii_kinds(detect:&str)->Vec<&'static str>{
    let d=detect.to_uppercase(); let mut v=vec![];
    if d.contains("EMAIL"){v.push("email");}
    if d.contains("NAME"){v.push("name");}
    if d.contains("GEO")||d.contains("REGION"){v.push("location");}
    if d.contains("PHONE"){v.push("phone");}
    if d.contains("IPV4")||d.contains("IPV6"){v.push("IP address");}
    if d.contains("DEVICE-ID"){v.push("device ID");}
    v
}

fn scoped<'a>(app:&'a App, scope:&str)->Vec<&'a Cookie>{
    match scope {
        "all"=>app.cookies.iter().collect(),
        s=>app.cookies.iter().filter(|c| c.dom==s || cookie_org(&c.name)==Some(s)).collect(),
    }
}

fn report_header(scope:&str, start:&str, now:&str, kind:&str)->String{
    let range = if start==now { format!("at {now}") } else { format!("{start} – {now}") };
    format!("# Panopticon — {kind}\n\nGenerated: {now} · Session: {range} · Scope: {scope}\n\n")
}

// ── TYPE 1: FULL AUDIT — everything, per-site cookies + trackers + sync + PII summary ──
fn report_audit(app:&App, scope:&str, start:&str, now:&str)->String{
    use std::collections::{HashSet,BTreeMap};
    let cookies=scoped(app,scope);
    let trackers=app.trackers();
    let mut o=report_header(scope,start,now,"Full Privacy Audit");

    let sites:HashSet<_>=cookies.iter().map(|c|c.dom.clone()).collect();
    o.push_str("## Overview\n\n");
    o.push_str(&format!("- {} sites set cookies\n- {} cookies total\n- {} tracking companies\n- {} sync identifiers\n- {} cookies carry personal data\n\n",
        sites.len(), cookies.len(), trackers.len(),
        cookies.iter().filter(|c|c.synced).count(),
        cookies.iter().filter(|c|!pii_kinds(&c.detect).is_empty()).count()));
    {   // per-browser breakdown, so a mixed-browser audit is unambiguous
        let mut bc:std::collections::BTreeMap<&str,usize>=std::collections::BTreeMap::new();
        for c in &cookies { *bc.entry(c.browser.as_str()).or_insert(0)+=1; }
        if bc.len()>1 {
            o.push_str("Cookies by browser: ");
            o.push_str(&bc.iter().map(|(b,n)|format!("{b} {n}")).collect::<Vec<_>>().join(" · "));
            let xb=cookies.iter().filter(|c|c.detect.contains("XBROWSER")).count();
            let same=cookies.iter().filter(|c|c.detect.contains("XBROWSER-SAME-ID")).count();
            o.push_str(&format!("\n\n{xb} cookies exist in more than one browser"));
            if same>0 { o.push_str(&format!(", {same} of them sharing the SAME identifier across browsers")); }
            o.push_str(".\n\n");
        }
    }

    o.push_str("## Trackers (by reach)\n\n");
    let trows:Vec<Vec<String>>=trackers.iter().map(|t|vec![
        t.org.clone(),t.sites.to_string(),format!("{}%",t.reach),t.topcat.clone(),
        if t.sync>0{"⇄".into()}else{String::new()},if t.live{"●".into()}else{String::new()}]).collect();
    o.push_str(&md_table(&["Tracker","Sites","Reach","Top data","Sync","Live"],&trows));
    o.push('\n');

    // per-site cookie breakdown, every cookie listed
    o.push_str("## Cookies by site (detailed)\n\n");
    let mut by_site:BTreeMap<String,Vec<&Cookie>>=BTreeMap::new();
    for c in &cookies { by_site.entry(c.dom.clone()).or_default().push(c); }
    for (site,cks) in &by_site {
        o.push_str(&format!("### {} ({} cookies)\n\n",site,cks.len()));
        let mut v=cks.clone(); v.sort_by(|a,b|b.entropy.partial_cmp(&a.entropy).unwrap());
        let rows:Vec<Vec<String>>=v.iter().map(|c|{
            let pii=pii_kinds(&c.detect);
            vec![c.name.clone(),c.browser.clone(),c.cat.clone(),format!("{:.1}",c.entropy),c.samesite.clone(),
                 if c.synced{"⇄".into()}else{String::new()},
                 if pii.is_empty(){String::new()}else{pii.join(",")}]
        }).collect();
        o.push_str(&md_table(&["Cookie","Browser","Category","Entropy","SameSite","Sync","PII"],&rows));
        o.push('\n');
    }

    o.push_str(&sync_section(scope));
    o.push_str(&pii_summary_section(&cookies));
    o.push_str("\n---\n_Full audit. Redacted — no raw values. Safe to share._\n");
    o
}

// ── TYPE 2: COOKIES DETAIL — every cookie, grouped by site, full attributes ──
fn report_cookies(app:&App, scope:&str, start:&str, now:&str)->String{
    use std::collections::BTreeMap;
    let cookies=scoped(app,scope);
    let mut o=report_header(scope,start,now,"Cookie Detail Report");
    o.push_str(&format!("{} cookies across {} sites.\n\n",
        cookies.len(), cookies.iter().map(|c|&c.dom).collect::<std::collections::HashSet<_>>().len()));
    let mut by_site:BTreeMap<String,Vec<&Cookie>>=BTreeMap::new();
    for c in &cookies { by_site.entry(c.dom.clone()).or_default().push(c); }
    for (site,cks) in &by_site {
        o.push_str(&format!("## {} ({} cookies)\n\n",site,cks.len()));
        let mut v=cks.clone(); v.sort_by(|a,b|b.entropy.partial_cmp(&a.entropy).unwrap());
        let rows:Vec<Vec<String>>=v.iter().map(|c|vec![
            c.name.clone(),c.browser.clone(),c.cat.clone(),format!("{:.1}",c.entropy),c.expiry.clone(),
            c.samesite.clone(),if c.synced{"⇄".into()}else{String::new()},
            if c.detect=="-"{String::new()}else{c.detect.clone()}]).collect();
        o.push_str(&md_table(&["Cookie","Browser","Category","Entropy","Expiry","SameSite","Sync","Detected"],&rows));
        o.push('\n');
    }
    o.push_str("\n---\n_Cookie detail. Redacted — no raw values. Safe to share._\n");
    o
}

// ── TYPE 3: PERSONAL DATA DETAIL — every PII item; redact flag controls values ──
fn report_pii(app:&App, scope:&str, start:&str, now:&str, redact:bool)->String{
    let cookies=scoped(app,scope);
    let kind=if redact {"Personal Data (redacted)"} else {"Personal Data (FULL — contains your data)"};
    let mut o=report_header(scope,start,now,kind);
    if !redact {
        o.push_str("> ⚠ This report contains your real personal data (name, email, payment,\n");
        o.push_str("> location). It is saved owner-only and gitignored. Keep it private.\n\n");
    }
    let pii:Vec<_>=cookies.iter().filter(|c|!pii_kinds(&c.detect).is_empty()).collect();
    if pii.is_empty(){
        o.push_str("No personal data found in cookie values.\n");
        return o;
    }
    o.push_str(&format!("{} cookies contain personal data.\n\n",pii.len()));
    // group by type
    use std::collections::BTreeMap;
    let mut by:BTreeMap<&str,Vec<&&Cookie>>=BTreeMap::new();
    for c in &pii { for k in pii_kinds(&c.detect){ by.entry(k).or_default().push(c); } }
    for (kind_name,items) in &by {
        o.push_str(&format!("## {} ({} found)\n\n",kind_name,items.len()));
        for c in items {
            if redact {
                o.push_str(&format!("- `{}` on **{}** _({})_\n",c.name,c.dom,c.browser));
            } else {
                let raw=fetch_value(&c.host,&c.name,&c.browser);
                let shown=if raw.contains('%'){ url_decode_str(&raw) } else { raw };
                o.push_str(&format!("- `{}` on **{}** _({})_\n  ```\n  {}\n  ```\n",c.name,c.dom,c.browser,shown));
            }
        }
        o.push('\n');
    }
    let tail=if redact{"Redacted — safe to share."}else{"FULL — contains your data. Keep private."};
    o.push_str(&format!("\n---\n_Personal data detail. {}_\n",tail));
    o
}

fn url_decode_str(v:&str)->String{
    let mut o=String::new(); let b=v.as_bytes(); let mut i=0;
    while i<b.len(){ if b[i]==b'%'&&i+2<b.len(){
        if let Ok(n)=u8::from_str_radix(&v[i+1..i+3],16){o.push(n as char);i+=3;continue;}}
        o.push(b[i] as char); i+=1; }
    o
}

fn sync_section(_scope:&str)->String{
    let clusters=std::fs::read_to_string("data/sync_clusters.tsv").unwrap_or_default();
    let rows:Vec<_>=clusters.lines().filter_map(|l|{
        let f:Vec<&str>=l.split('\t').collect();
        if f.len()<4 {return None;}
        Some((f[3].to_string(),f[2].to_string(),f[1].replace(',',", ")))
    }).collect();
    if rows.is_empty(){return String::new();}
    let mut o=String::from("## Cross-site identity sharing\n\nThe same hidden ID on multiple sites — these companies can merge your activity:\n\n");
    for (org,cookie,doms) in &rows {
        o.push_str(&format!("- **{}** links {} (via `{}`, value [redacted])\n",org,doms,cookie));
    }
    o.push('\n'); o
}

fn pii_summary_section(cookies:&[&Cookie])->String{
    use std::collections::{BTreeMap,BTreeSet};
    let mut by:BTreeMap<&str,BTreeSet<String>>=BTreeMap::new();
    for c in cookies { for k in pii_kinds(&c.detect){ by.entry(k).or_default().insert(c.dom.clone()); } }
    if by.is_empty(){return String::from("## Personal data exposure\n\nNone found in cookie values.\n\n");}
    let mut o=String::from("## Personal data exposure (redacted)\n\n");
    for (k,sites) in &by {
        o.push_str(&format!("- **{}** on {} site(s): {}\n",k,sites.len(),
            sites.iter().cloned().collect::<Vec<_>>().join(", ")));
    }
    o.push('\n'); o
}

fn write_report(app:&App, scope:&str, rtype:&str, redact:bool)->std::io::Result<String>{
    use std::io::Write;
    std::fs::create_dir_all("data/reports").ok();
    let now=chrono_now(); let start=app.session_start.clone();
    let (body, private) = match rtype {
        "audit"   => (report_audit(app,scope,&start,&now), false),
        "cookies" => (report_cookies(app,scope,&start,&now), false),
        "pii"     => (report_pii(app,scope,&start,&now,redact), !redact),
        _         => (report_audit(app,scope,&start,&now), false),
    };
    let safe=scope.replace(['/','.',' '],"_");
    let tag=if rtype=="pii" && !redact {"pii_full"} else {rtype};
    let fname=format!("data/reports/{}_{}_{}.md", now.replace([':',' '],"-"), safe, tag);
    let mut f=std::fs::File::create(&fname)?;
    f.write_all(body.as_bytes())?;
    #[cfg(unix)]
    if private { use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fname, std::fs::Permissions::from_mode(0o600)).ok(); }
    Ok(fname)
}

fn chrono_now()->String{
    // lightweight timestamp without pulling chrono: use SystemTime
    use std::time::{SystemTime,UNIX_EPOCH};
    let secs=SystemTime::now().duration_since(UNIX_EPOCH).map(|d|d.as_secs()).unwrap_or(0);
    // format as local-ish: just epoch-based date string via a simple conversion
    let days=secs/86400; let tod=secs%86400;
    let (h,m)=((tod/3600),(tod%3600)/60);
    // rough Y-M-D from epoch days (good enough for a filename/label)
    let z=days as i64 + 719468;
    let era=if z>=0{z}else{z-146096}/146097;
    let doe=z-era*146097;
    let yoe=(doe-doe/1460+doe/36524-doe/146096)/365;
    let y=yoe+era*400;
    let doy=doe-(365*yoe+yoe/4-yoe/100);
    let mp=(5*doy+2)/153;
    let d=doy-(153*mp+2)/5+1;
    let mth=if mp<10{mp+3}else{mp-9};
    let year=if mth<=2{y+1}else{y};
    format!("{:04}-{:02}-{:02} {:02}:{:02}",year,mth,d,h,m)
}

fn draw_export(f:&mut Frame,a:Rect,app:&App){
    if app.export==ExportStage::None && app.export_msg.is_none() { return; }
    let y=Color::Yellow; let w=Color::White; let g=Color::Gray;
    let lines:Vec<Line> = if let Some(msg)=&app.export_msg {
        vec![
            Line::from(Span::styled(msg.clone(),Style::new().fg(if msg.starts_with("✓"){Color::Green}else{Color::Red}).bold())),
            Line::from(""),
            Line::from(Span::styled("press any key to continue",Style::new().fg(g))),
        ]
    } else { match app.export {
        ExportStage::Scope => vec![
            Line::from(Span::styled("Export — choose scope:",Style::new().fg(y).bold())),
            Line::from(""),
            Line::from(vec![Span::styled("  [c] ",Style::new().fg(w).bold()),Span::styled("current site / tracker",Style::new().fg(g))]),
            Line::from(vec![Span::styled("  [a] ",Style::new().fg(w).bold()),Span::styled("everything (all sites)",Style::new().fg(g))]),
            Line::from(vec![Span::styled("  [Esc] cancel",Style::new().fg(g))]),
        ],
        ExportStage::Type => vec![
            Line::from(Span::styled(format!("Scope: {} — choose report:",app.export_scope),Style::new().fg(y).bold())),
            Line::from(""),
            Line::from(vec![Span::styled("  [1] ",Style::new().fg(w).bold()),Span::styled("Full audit — trackers, cookies per site, sync, PII summary",Style::new().fg(g))]),
            Line::from(vec![Span::styled("  [2] ",Style::new().fg(w).bold()),Span::styled("Cookie detail — every cookie, grouped by site",Style::new().fg(g))]),
            Line::from(vec![Span::styled("  [3] ",Style::new().fg(w).bold()),Span::styled("Personal data — every PII item found",Style::new().fg(g))]),
            Line::from(vec![Span::styled("  [Esc] cancel",Style::new().fg(g))]),
        ],
        ExportStage::PiiRedact => vec![
            Line::from(Span::styled("Personal data report — show real values?",Style::new().fg(y).bold())),
            Line::from(""),
            Line::from(vec![Span::styled("  [s] ",Style::new().fg(Color::Green).bold()),Span::styled("redacted — lists what & where, safe to share",Style::new().fg(g))]),
            Line::from(vec![Span::styled("  [f] ",Style::new().fg(Color::Red).bold()),Span::styled("full values — YOUR data, saved owner-only & private",Style::new().fg(g))]),
            Line::from(vec![Span::styled("  [Esc] cancel",Style::new().fg(g))]),
        ],
        ExportStage::None => vec![],
    }};
    // center a small box
    let bw=64.min(a.width.saturating_sub(4)); let bh=(lines.len()as u16)+2;
    let bx=a.x+(a.width.saturating_sub(bw))/2; let by=a.y+(a.height.saturating_sub(bh))/2;
    let rect=Rect{x:bx,y:by,width:bw,height:bh};
    f.render_widget(Clear,rect);
    f.render_widget(Paragraph::new(lines)
        .block(Block::bordered().border_style(Style::new().fg(y)).title(" export (e) ")),rect);
}

fn draw_footer(f:&mut Frame,a:Rect,app:&App){
    if app.expanded {
        if let Some(c)=app.selected_cookie(){
            let c=&c;
            let mut lines=vec![
                Line::from(vec![Span::styled("name: ",Style::new().fg(Color::Yellow)),Span::raw(&c.name)]),
                Line::from(vec![Span::styled("host: ",Style::new().fg(Color::Yellow)),Span::raw(&c.host)]),
                Line::from(vec![Span::styled("browser: ",Style::new().fg(Color::Yellow)),
                    Span::styled(c.browser.clone(),Style::new().fg(browser_color(&c.browser)))]),
                Line::from(vec![Span::styled("category: ",Style::new().fg(Color::Yellow)),
                    Span::styled(format!("{} / {}",c.cat,c.sub),Style::new().fg(cat_color(&c.cat)))]),
                Line::from(vec![Span::styled("entropy: ",Style::new().fg(Color::Yellow)),
                    Span::raw(format!("{:.2}  ",c.entropy)),
                    Span::styled(if c.entropy>4.0{"high — identifier-grade"}else if c.entropy>3.0{"moderate"}else{"low — not an ID"},
                        Style::new().fg(if c.entropy>4.0{Color::Red}else{Color::Gray}))]),
                Line::from(vec![Span::styled("expiry: ",Style::new().fg(Color::Yellow)),Span::raw(&c.expiry),
                    Span::raw("   "),Span::styled("sameSite: ",Style::new().fg(Color::Yellow)),Span::raw(&c.samesite)]),
                Line::from(vec![Span::styled("sync: ",Style::new().fg(Color::Yellow)),
                    Span::styled(
                        if c.synced {
                            let ps=sync_partners(&c.vhash,&c.dom);
                            if ps.is_empty(){"⇄ same value seen on another site (partner not resolved)".to_string()}
                            else{format!("⇄ SAME VALUE ALSO ON: {} — these sites can be linked", ps.join(", "))}
                        } else if c.same_owner {
                            let ps=sync_partners(&c.vhash,&c.dom);
                            format!("⇄ also on {} — same owner, not third-party sharing",
                                if ps.is_empty(){"the same company's other sites".to_string()}else{ps.join(", ")})
                        } else {"not shared".to_string()},
                        Style::new().fg(if c.synced{Color::Red}
                            else if c.same_owner{Color::Yellow}else{Color::Green}).bold())]),
                Line::from(vec![Span::styled("DETECTED IN VALUE: ",Style::new().fg(Color::LightRed).bold()),
                    Span::styled(if c.detect=="-"{"opaque identifier (no decodable fields)".to_string()}
                                 else{c.detect.clone()},
                        Style::new().fg(if c.detect=="-"{Color::Gray}else{Color::Red}).bold())]),
                Line::from(vec![Span::styled("RAW VALUE: ",Style::new().fg(Color::Yellow).bold())]),
                Line::from(Span::styled(fetch_value(&c.host,&c.name,&c.browser), Style::new().fg(Color::White))),
            ];
            let this_key=cookie_key(c);
            if let Some(trace)=app.decoded.get(&this_key) {
                lines.push(Line::from(Span::styled("─── deep decode (cached this session) ───",
                    Style::new().fg(Color::Cyan).bold())));
                for (dl,ok) in trace.iter().take(12){
                    if dl.starts_with("▪ DONE"){
                        lines.push(Line::from(Span::styled(dl.clone(),
                            Style::new().fg(if *ok{Color::Green}else{Color::Yellow}).bold())));
                    } else {
                        let mark = if *ok {"✓ "} else {"· "};
                        let col = if *ok {Color::LightGreen} else {Color::Gray};
                        lines.push(Line::from(vec![
                            Span::styled(mark,Style::new().fg(if *ok{Color::Green}else{Color::Red})),
                            Span::styled(dl.clone(),Style::new().fg(col))]));
                    }
                }
            } else if c.candecode {
                lines.push(Line::from(Span::styled("▸ press d to decode (this value has a peelable layer)",
                    Style::new().fg(Color::Cyan))));
            } else {
                lines.push(Line::from(Span::styled("· nothing to decode — opaque identifier or already plaintext",
                    Style::new().fg(Color::DarkGray))));
            }
            f.render_widget(Paragraph::new(lines).wrap(ratatui::widgets::Wrap{trim:false})
                .scroll((app.detail_scroll,0))
                .block(Block::bordered().title(" cookie detail — PgUp/PgDn to scroll ")),a);
            return;
        }
    }
    let help=Paragraph::new(Line::from(vec![
        Span::styled(" Tab ",Style::new().bg(Color::DarkGray)),Span::raw(" switch view  "),
        Span::styled(" ↑↓ ",Style::new().bg(Color::DarkGray)),Span::raw(" select  "),
        Span::styled(" Enter ",Style::new().bg(Color::DarkGray)),Span::raw(" detail  "),
        Span::styled(" d ",Style::new().bg(Color::DarkGray)),Span::raw(" decode  "),
        Span::styled(" / ",Style::new().bg(Color::DarkGray)),Span::raw(" search  "),
        Span::styled(" b ",Style::new().bg(Color::DarkGray)),Span::raw(" browser  "),
        Span::styled(" e ",Style::new().bg(Color::DarkGray)),Span::raw(" export  "),Span::styled(" ? ",Style::new().bg(Color::DarkGray)),Span::raw(" help  "),Span::styled(" q ",Style::new().bg(Color::DarkGray)),Span::raw(" quit "),
    ])).block(Block::bordered());
    f.render_widget(help,a);
}
