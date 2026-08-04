use std::{collections::{HashMap, HashSet, BTreeMap}, fs};

// collapse "Google Analytics", "Google Ads", "Google DoubleClick" -> "Google"
fn parent(org: &str) -> &str {
    let o = org.to_lowercase();
    if o.contains("google") { "Google" }
    else if o.contains("meta") || o.contains("facebook") { "Meta" }
    else if o.contains("microsoft") { "Microsoft" }
    else if o.contains("amazon") { "Amazon" }
    else if o.contains("cloudflare") { "Cloudflare" }
    else if o.contains("fastly") { "Fastly" }
    else if o.contains("segment") || o.contains("twilio") { "Twilio" }
    else { org }
}


// (network_u32, mask_bits, org)
// ASN data lives in data/static/asn_v4.tsv + asn_v6.tsv (written by fetch-data.sh)
// and is loaded by the shared AsnDb, which binary-searches it. This used to read a
// data/asn_ranges.txt that nothing ever produced, so every lookup here returned None.
fn load_asn() -> crate::asn::AsnDb { crate::asn::AsnDb::load() }

fn asn_lookup(ip: &str, table: &crate::asn::AsnDb) -> Option<String> { table.lookup(ip) }

fn label_entropy(host: &str) -> f64 {
    let label = host.split('.').next().unwrap_or(host);
    if label.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    for &b in label.as_bytes() { freq[b as usize] += 1; }
    let n = label.len() as f64;
    freq.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n; -p * p.log2()
    }).sum()
}

pub fn run() -> anyhow::Result<()> {
    let asn = load_asn();

    // --- org -> set of sites it cookied (from P2) ---
    // cookies.tsv columns: browser(0) host(1) name(2) tracker_org(3) id_kind(4) flags(5)
    // The org is column 3. Column 4 is the identifier *kind* ("ad-id", "cross-site
    // ID") and must not be treated as a company name.
    let mut cookie_orgs: HashMap<String, HashSet<String>> = HashMap::new();
    for l in fs::read_to_string("data/cookies.tsv").unwrap_or_default().lines().skip(1) {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 6 || f[3] == "-" { continue; }
        cookie_orgs.entry(parent(f[3]).to_string()).or_default()
            .insert(f[1].trim_start_matches('.').to_string());
    }

    // An org seen on at least one site it does not own is a third party.
    // cookies.tsv has no party column, so derive it from the cookie_detail export
    // when present, else treat everything as third party (the cautious default is
    // to keep the entry visible rather than silently downgrade it).
    let mut third_party: HashSet<String> = HashSet::new();
    let mut first_party: HashSet<String> = HashSet::new();
    for l in fs::read_to_string("data/cookies_detail.tsv").unwrap_or_default().lines().skip(1) {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 15 { continue; }
        match f[14] {
            "third" => { third_party.insert(parent(f[13]).to_string()); }
            "first" => { first_party.insert(parent(f[13]).to_string()); }
            _ => {}
        }
    }

    if cookie_orgs.is_empty() {
        eprintln!("[panopticon] warning: no tracker orgs in data/cookies.tsv \
                   — run --cookies first (and ./fetch-data.sh if you have not). \
                   Correlation results below will be empty.");
    }

    // --- live network destinations (from P1), resolved via DNS then ASN ---
    let mut live_orgs: HashMap<String, HashSet<String>> = HashMap::new(); // org -> hosts/ips
    let mut silent: BTreeMap<String, (String, f64)> = BTreeMap::new();     // ip -> (comm, entropy)
    let mut resolved = 0u32;
    for l in fs::read_to_string("data/flows.log").unwrap_or_default().lines() {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 5 { continue; }
        let comm = f[0];
        let ipport = f[3];
        let host = f[4];
        let ip = ipport.rsplit_once(':').map(|(i,_)| i).unwrap_or(ipport);
        // map to an org: prefer DNS name match against cookie orgs' known tracker domains,
        // else ASN owner of the IP
        let org = asn_lookup(ip, &asn);
        match org {
            Some(o) => { resolved += 1;
                live_orgs.entry(parent(&o).to_string()).or_default()
                    .insert(if host != "?" { host.to_string() } else { ip.to_string() }); }
            None if host == "?" => {
                // unresolved + unknown ASN = silent talker candidate
                let e = if ip.contains(':') { 0.0 } else { label_entropy(ip) };
                silent.insert(ip.to_string(), (comm.to_string(), e));
            }
            None => {}
        }
    }

    // --- confirmed active-sharing edges: org present in BOTH jar and live traffic ---
    println!("\n=== CONFIRMED ACTIVE SHARING (cookied AND contacted live) ===");
    let mut confirmed = 0;
    for (org, sites) in &cookie_orgs {
        if let Some(live) = live_orgs.get(org) {
            confirmed += 1;
            println!("  ⚡ {org}");
            println!("       cookied on {} sites, contacted {} live endpoint(s)",
                sites.len(), live.len());
            for ep in live.iter().take(3) { println!("       └─ live: {ep}"); }
        }
    }
    if confirmed == 0 {
        println!("  (none yet — run --watch during real browsing to populate flows.log)");
    }

    println!("\n=== COOKIED, NOT SEEN ON WIRE THIS SESSION ===");
    println!("  (third-party = present on sites it does not own; first-party = its own sites)");
    let mut dormant: Vec<_> = cookie_orgs.iter()
        .filter(|(o, _)| !live_orgs.contains_key(*o))
        .map(|(o, s)| {
            let p = if third_party.contains(o) {1u8}
                    else if first_party.contains(o) {2} else {0};
            (s.len(), o.clone(), p)
        }).collect();
    // third parties first — those are the ones following you across sites
    dormant.sort_by(|a, b| (b.2==1).cmp(&(a.2==1)).then(b.0.cmp(&a.0)));
    for (n, o, p) in dormant.iter().take(12) {
        println!("  · {o} ({n} sites) [{}]",
            match p {1=>"third-party",2=>"first-party",_=>"unattributed"});
    }

    println!("\n=== SILENT TALKERS (egress, no DNS name, no known ASN) ===");
    if silent.is_empty() { println!("  (none)"); }
    for (ip, (comm, e)) in silent.iter().take(10) {
        let flag = if *e > 3.0 { " ⚠ high-entropy" } else { "" };
        println!("  ? {comm} → {ip}  entropy={e:.2}{flag}");
    }

    println!("\n[panopticon] flows resolved to org: {resolved} | active edges: {confirmed} \
             | silent: {}", silent.len());
    Ok(())
}
