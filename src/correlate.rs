use std::{collections::{HashMap, HashSet, BTreeMap}, fs, net::Ipv4Addr};

fn ip_to_u32(s: &str) -> Option<u32> {
    s.parse::<Ipv4Addr>().ok().map(|a| u32::from(a))
}


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


fn ip6_to_u128(s: &str) -> Option<u128> {
    s.parse::<std::net::Ipv6Addr>().ok().map(u128::from)
}

fn cidr6_match(ip: &str, net: &str, bits: u32) -> bool {
    match (ip6_to_u128(ip), ip6_to_u128(net)) {
        (Some(v), Some(n)) => {
            let mask = if bits == 0 { 0u128 } else { u128::MAX << (128 - bits) };
            (v & mask) == (n & mask)
        }
        _ => false,
    }
}

// (network_u32, mask_bits, org)
fn load_asn() -> Vec<(String, u32, String)> {
    fs::read_to_string("data/asn_ranges.txt").unwrap_or_default().lines()
        .filter_map(|l| {
            let (cidr, org) = l.split_once('\t')?;
            let (net, bits) = cidr.split_once('/')?;
            let b: u32 = bits.parse().ok()?;
            Some((net.to_string(), b, org.to_string()))
        }).collect()
}

fn asn_lookup(ip: &str, table: &[(String, u32, String)]) -> Option<String> {
    let is_v6 = ip.contains(':');
    for (net, bits, org) in table {
        let net_v6 = net.contains(':');
        if net_v6 != is_v6 { continue; }
        let hit = if is_v6 {
            cidr6_match(ip, net, *bits)
        } else {
            match (ip_to_u32(ip), ip_to_u32(net)) {
                (Some(v), Some(n)) => {
                    let mask = if *bits == 0 { 0 } else { u32::MAX << (32 - bits) };
                    (v & mask) == (n & mask)
                }
                _ => false,
            }
        };
        if hit { return Some(org.clone()); }
    }
    None
}

// Shannon entropy of the domain label — high = random-looking (DGA / opaque endpoint)
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

    println!("\n=== DORMANT TRACKERS (cookied, not seen on wire this session) ===");
    let mut dormant: Vec<_> = cookie_orgs.iter()
        .filter(|(o, _)| !live_orgs.contains_key(*o))
        .map(|(o, s)| (s.len(), o.clone())).collect();
    dormant.sort_by(|a, b| b.0.cmp(&a.0));
    for (n, o) in dormant.iter().take(8) { println!("  · {o} ({n} sites)"); }

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
