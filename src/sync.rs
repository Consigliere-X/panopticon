use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fs, io::Write, path::PathBuf};

// registrable-domain approximation: last two labels (good enough w/o a PSL)
fn etld1(host: &str) -> String {
    let h = host.trim_start_matches('.');
    let parts: Vec<&str> = h.rsplitn(3, '.').collect();
    if parts.len() >= 2 { format!("{}.{}", parts[1], parts[0]) } else { h.to_string() }
}

// Shannon entropy over the value bytes — filters "1"/"true"/"en_US" noise
fn entropy(v: &str) -> f64 {
    if v.is_empty() { return 0.0; }
    let mut f = [0u32; 256];
    for &b in v.as_bytes() { f[b as usize] += 1; }
    let n = v.len() as f64;
    f.iter().filter(|&&c| c > 0).map(|&c| { let p = c as f64/n; -p*p.log2() }).sum()
}

fn find_firefox() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let base = PathBuf::from(&home).join(".config/mozilla/firefox");
    let alt  = PathBuf::from(&home).join(".mozilla/firefox");
    let mut out = vec![];
    for root in [base, alt] {
        if !root.exists() { continue; }
        for e in fs::read_dir(&root).into_iter().flatten().flatten() {
            let db = e.path().join("cookies.sqlite");
            if db.exists() { out.push(db); }
        }
    }
    out
}

fn read_values(db: &PathBuf) -> Vec<(String, String, String)> { // (host, name, value)
    let uri = format!("file:{}?immutable=1", db.display());
    let conn = match Connection::open_with_flags(&uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI) { Ok(c)=>c, Err(_)=>return vec![] };
    let mut q = match conn.prepare("SELECT host, name, value FROM moz_cookies WHERE length(value)>=8")
        { Ok(q)=>q, Err(_)=>return vec![] };
    q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map(|rows| rows.filter_map(|x| x.ok()).collect()).unwrap_or_default()
}

pub fn run() -> anyhow::Result<()> {
    fs::create_dir_all("data").ok();
    // value_hash -> set of (etld1, cookie_name, entropy)
    let mut by_val: HashMap<String, Vec<(String, String, f64)>> = HashMap::new();

    for db in find_firefox() {
        for (host, name, value) in read_values(&db) {
            let e = entropy(&value);
            if e < 3.0 { continue; }                 // skip low-entropy / non-identifier values
            let nl = name.to_lowercase();
            if nl.contains("consent") || nl.contains("preference")
               || nl.contains("gdpr") || nl.contains("cookie_policy") { continue; }
            if value.len() < 10 { continue; }
            let mut h = Sha256::new(); h.update(value.as_bytes());
            let hash = format!("{:x}", h.finalize());
            let dom = etld1(&host);
            let bucket = by_val.entry(hash).or_default();
            if !bucket.iter().any(|(d, n, _)| d == &dom && n == &name) {
                bucket.push((dom, name, e));
            }
        }
    }

    
// domains owned by the same entity — a shared ID here is first-party, not a broker sync
fn same_owner(a: &str, b: &str) -> bool {
    const CLUSTERS: &[&[&str]] = &[
        &["openai.com", "chatgpt.com", "oaistatic.com"],
        &["anthropic.com", "claude.ai", "claude.com"],
        &["google.com", "youtube.com", "gstatic.com", "googleapis.com"],
        &["facebook.com", "instagram.com", "meta.com", "fb.com"],
        &["amazon.com", "amazon.in", "aws.amazon.com"],
        &["microsoft.com", "live.com", "bing.com", "office.com"],
    ];
    CLUSTERS.iter().any(|c| c.contains(&a) && c.contains(&b))
}

    // a SYNC = one value shared across >=2 DISTINCT registrable domains
    let mut syncs: Vec<(&String, &Vec<(String,String,f64)>)> = by_val.iter()
        .filter(|(_, v)| {
            let doms: Vec<&String> = {
                let set: std::collections::HashSet<_> = v.iter().map(|(d,_,_)| d).collect();
                set.into_iter().collect()
            };
            if doms.len() < 2 { return false; }
            // keep only if some pair is cross-owner
            doms.iter().enumerate().any(|(i, a)|
                doms.iter().skip(i+1).any(|b| !same_owner(a, b)))
        }).collect();
    syncs.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    let mut out = fs::File::create("data/sync_edges.tsv")?;
    writeln!(out, "value_hash\tdomains\tcookie_names\tmax_entropy")?;

    println!("\n=== COOKIE-SYNC: identifiers shared across unrelated domains ===");
    if syncs.is_empty() {
        println!("  (none detected — trackers may be using per-site salted IDs, which is itself a finding)");
    }
    for (hash, members) in syncs.iter().take(20) {
        let doms: std::collections::BTreeSet<_> = members.iter().map(|(d,_,_)| d.as_str()).collect();
        let names: std::collections::BTreeSet<_> = members.iter().map(|(_,n,_)| n.as_str()).collect();
        let maxe = members.iter().map(|(_,_,e)| *e).fold(0.0, f64::max);
        println!("  ⇄ {} domains share one ID [{}]  entropy={:.1}",
            doms.len(), doms.iter().cloned().collect::<Vec<_>>().join(" ↔ "), maxe);
        println!("       cookie names: {}", names.iter().cloned().collect::<Vec<_>>().join(", "));
        writeln!(out, "{}\t{}\t{}\t{:.2}", &hash[..12],
            doms.iter().cloned().collect::<Vec<_>>().join(","),
            names.iter().cloned().collect::<Vec<_>>().join(","), maxe)?;
    }
    println!("\n[panopticon] sync edges: {} | scanned values with entropy>=3.0", syncs.len());
    Ok(())
}
