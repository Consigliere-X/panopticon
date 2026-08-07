use rusqlite::{Connection, OpenFlags};
use std::{collections::HashMap, fs, io::Write, path::PathBuf};
use walkdir::WalkDir;

fn load_map(path: &str) -> HashMap<String, String> {
    fs::read_to_string(path).unwrap_or_default().lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

// classify a cookie name against known id-fingerprints (prefix-aware for mp_/ajs_)
fn id_kind(name: &str, ids: &HashMap<String, String>) -> Option<String> {
    if let Some(v) = ids.get(name) { return Some(v.clone()); }
    ids.iter().find(|(k, _)| k.ends_with('_') && name.starts_with(*k))
        .map(|(_, v)| v.clone())
}

fn tracker_of(host: &str, tr: &HashMap<String, String>) -> Option<String> {
    // Walk the host's own suffixes (a.b.example.com -> b.example.com -> example.com)
    // doing hash lookups, instead of scanning every entry in the Radar map for each
    // cookie — that was O(cookies x trackers) with an allocation per comparison.
    let mut h = host.trim_start_matches('.');
    loop {
        if let Some(org) = tr.get(h) { return Some(org.clone()); }
        match h.split_once('.') {
            Some((_, rest)) if rest.contains('.') => h = rest,
            _ => return None,
        }
    }
}

fn find_stores() -> Vec<(String, PathBuf)> {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut out = vec![];
    for root in [".mozilla/firefox", ".config", ".var/app"] {
        let base = PathBuf::from(&home).join(root);
        if !base.exists() { continue; }
        for e in WalkDir::new(&base).max_depth(6).into_iter().filter_map(|e| e.ok()) {
            let p = e.path();
            match p.file_name().and_then(|n| n.to_str()) {
                Some("cookies.sqlite") => out.push(("firefox".into(), p.to_path_buf())),
                Some("Cookies") if p.to_string_lossy().contains("/Network/")
                    || p.parent().map_or(false, |d| d.join("Preferences").exists())
                    => out.push(("chromium".into(), p.to_path_buf())),
                _ => {}
            }
        }
    }
    out
}

fn read_firefox(db: &PathBuf) -> Vec<(String, String, i64, i32)> {
    let uri = format!("file:{}?immutable=1", db.display());
    let conn = match Connection::open_with_flags(&uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI) { Ok(c) => c, Err(_) => return vec![] };
    let mut q = match conn.prepare(
        "SELECT host, name, expiry, sameSite FROM moz_cookies") { Ok(q) => q, Err(_) => return vec![] };
    q.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?,
        r.get::<_,i64>(2).unwrap_or(0), r.get::<_,i32>(3).unwrap_or(-1))))
        .map(|rows| rows.filter_map(|x| x.ok()).collect()).unwrap_or_default()
}

fn read_chromium(db: &PathBuf) -> Vec<(String, String, i64, i32)> {
    let uri = format!("file:{}?immutable=1", db.display());
    let conn = match Connection::open_with_flags(&uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI) { Ok(c) => c, Err(_) => return vec![] };
    let mut q = match conn.prepare(
        "SELECT host_key, name, expires_utc, samesite FROM cookies") { Ok(q) => q, Err(_) => return vec![] };
    q.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?,
        r.get::<_,i64>(2).unwrap_or(0), r.get::<_,i32>(3).unwrap_or(-1))))
        .map(|rows| rows.filter_map(|x| x.ok()).collect()).unwrap_or_default()
}

pub fn run() -> anyhow::Result<()> {
    fs::create_dir_all("data").ok();
    // Tracker Radar lives under data/static/ (fetched by fetch-data.sh), with local
    // overrides layered on top — same sources enrich.rs uses. Loading the wrong path
    // here silently left tracker_org empty for every cookie.
    let mut trackers = load_map("data/static/trackers.tsv");
    trackers.extend(load_map("data/static/trackers_override.tsv"));
    if trackers.is_empty() {
        eprintln!("[panopticon] warning: no tracker data at data/static/trackers.tsv \
                   — run ./fetch-data.sh; tracker_org will be empty");
    }
    // Shipped seed first, then any local data/id_cookies.txt as an override, so a
    // fresh clone gets useful labels instead of silently having none.
    let mut ids = load_map("data/static/id_cookies.tsv");
    ids.extend(load_map("data/id_cookies.txt"));
    let stores = find_stores();
    if stores.is_empty() { eprintln!("[panopticon] no cookie stores found"); return Ok(()); }

    let mut out = fs::File::create("data/cookies.tsv")?;
    writeln!(out, "browser\thost\tname\ttracker_org\tid_kind\tflags")?;
    let (mut total, mut tracking, mut identifiers) = (0u32, 0u32, 0u32);

    for (browser, db) in &stores {
        eprintln!("[panopticon] scanning {browser} :: {}", db.display());
        let rows = if browser == "firefox" { read_firefox(db) } else { read_chromium(db) };
        for (host, name, expiry, samesite) in rows {
            total += 1;
            let torg = tracker_of(&host, &trackers);
            let ik = id_kind(&name, &ids);
            if torg.is_some() || ik.is_some() { tracking += 1; }
            if ik.is_some() { identifiers += 1; }
            let ss = match samesite { 0 => "none", 1 => "lax", 2 => "strict", _ => "?" };
            let persist = if expiry > 0 { "persistent" } else { "session" };
            writeln!(out, "{browser}\t{host}\t{name}\t{}\t{}\t{ss};{persist}",
                torg.unwrap_or_else(|| "-".into()),
                ik.unwrap_or_else(|| "-".into()))?;
        }
    }
    eprintln!("[panopticon] cookies={total} tracking={tracking} identifiers={identifiers}");
    println!("SUMMARY total={total} tracking={tracking} identifiers={identifiers} \
             stores={}", stores.len());
    Ok(())
}
