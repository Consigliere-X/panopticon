// DNS tap — sniffs plaintext port-53 responses, writes IP->domain to data/dns.log.
// Runs as a thread inside the daemon so flows can resolve hostnames.
use std::{collections::HashMap, fs, fs::OpenOptions, io::Write};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{ethernet::{EtherTypes, EthernetPacket}, ip::IpNextHeaderProtocols,
                   ipv4::Ipv4Packet, udp::UdpPacket, Packet};

fn read_name(b: &[u8], mut p: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut jumped = false;
    let mut ret = 0usize;
    let mut hops = 0;
    loop {
        if p >= b.len() { return None; }
        let len = b[p] as usize;
        if len == 0 { if !jumped { ret = p + 1; } break; }
        if len & 0xC0 == 0xC0 {
            if p + 1 >= b.len() { return None; }
            let off = ((len & 0x3F) << 8) | b[p+1] as usize;
            if !jumped { ret = p + 2; }
            p = off; jumped = true; hops += 1;
            if hops > 20 { return None; }
            continue;
        }
        p += 1;
        if p + len > b.len() { return None; }
        if !out.is_empty() { out.push('.'); }
        out.push_str(&String::from_utf8_lossy(&b[p..p+len]));
        p += len;
    }
    Some((out, if jumped { ret } else { p }))
}

fn parse_dns(b: &[u8]) -> Vec<(String, String)> {
    let mut v = vec![];
    if b.len() < 12 { return v; }
    let qd = u16::from_be_bytes([b[4], b[5]]) as usize;
    let an = u16::from_be_bytes([b[6], b[7]]) as usize;
    let mut p = 12;
    for _ in 0..qd {
        match read_name(b, p) { Some((_, n)) => p = n + 4, None => return v }
    }
    for _ in 0..an {
        let name = match read_name(b, p) { Some((n, np)) => { p = np; n }, None => return v };
        if p + 10 > b.len() { return v; }
        let typ = u16::from_be_bytes([b[p], b[p+1]]);
        let rdlen = u16::from_be_bytes([b[p+8], b[p+9]]) as usize;
        p += 10;
        if p + rdlen > b.len() { return v; }
        match typ {
            1 if rdlen == 4 => {
                let ip = format!("{}.{}.{}.{}", b[p], b[p+1], b[p+2], b[p+3]);
                v.push((name, ip));
            }
            28 if rdlen == 16 => {
                let mut seg = [0u16; 8];
                for i in 0..8 { seg[i] = u16::from_be_bytes([b[p+i*2], b[p+i*2+1]]); }
                let ip = std::net::Ipv6Addr::new(seg[0],seg[1],seg[2],seg[3],seg[4],seg[5],seg[6],seg[7]).to_string();
                v.push((name, ip));
            }
            _ => {}
        }
        p += rdlen;
    }
    v
}

pub fn dns_tap_loop() {
    fs::create_dir_all("data").ok();
    let iface = match datalink::interfaces().into_iter()
        .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty()) {
        Some(i) => i, None => { eprintln!("[panopticon] dns-tap: no interface"); return; }
    };
    eprintln!("[panopticon] dns-tap thread :: {}", iface.name);
    let mut rx = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        _ => { eprintln!("[panopticon] dns-tap: need cap_net_raw"); return; }
    };
    let mut log = match OpenOptions::new().create(true).append(true).open("data/dns.log") {
        Ok(f) => f, Err(_) => return
    };
    let mut cache: HashMap<String, String> = HashMap::new();
    loop {
        let frame = match rx.next() { Ok(f) => f, Err(_) => continue };
        let eth = match EthernetPacket::new(frame) { Some(e) => e, None => continue };
        if eth.get_ethertype() != EtherTypes::Ipv4 { continue; }
        let ip = match Ipv4Packet::new(eth.payload()) { Some(i) => i, None => continue };
        if ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp { continue; }
        let udp = match UdpPacket::new(ip.payload()) { Some(u) => u, None => continue };
        if udp.get_source() != 53 { continue; }
        for (name, val) in parse_dns(udp.payload()) {
            if cache.insert(val.clone(), name.clone()).as_deref() != Some(name.as_str()) {
                writeln!(log, "{val} {name}").ok(); log.flush().ok();
            }
        }
    }
}
