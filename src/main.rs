mod dns;
mod asn;
mod tui_app;
mod enrich;
mod tui_stream;
mod server;
mod wire;
mod sync;
mod tui;
mod correlate;
mod cookies;
mod chromium;
mod flow;
use std::{collections::HashMap, env, fs, fs::OpenOptions, io::Write};
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::{ethernet::{EtherTypes, EthernetPacket}, ip::IpNextHeaderProtocols,
                   ipv4::Ipv4Packet, udp::UdpPacket, Packet};

fn read_name(b: &[u8], mut p: usize) -> Option<(String, usize)> {
    let (mut out, mut jumped, mut next, mut hops) = (String::new(), false, 0usize, 0);
    loop {
        if p >= b.len() { return None; }
        let len = b[p] as usize;
        if len == 0 { p += 1; if !jumped { next = p; } break; }
        if len & 0xC0 == 0xC0 {
            if p + 1 >= b.len() { return None; }
            let ptr = ((len & 0x3F) << 8) | b[p + 1] as usize;
            if !jumped { next = p + 2; }
            jumped = true; p = ptr; hops += 1;
            if hops > 16 { return None; }
            continue;
        }
        p += 1;
        if p + len > b.len() { return None; }
        if !out.is_empty() { out.push('.'); }
        out.push_str(&String::from_utf8_lossy(&b[p..p + len]));
        p += len;
    }
    Some((out, next))
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
        let rtype = u16::from_be_bytes([b[p], b[p + 1]]);
        let rdlen = u16::from_be_bytes([b[p + 8], b[p + 9]]) as usize;
        p += 10;
        if p + rdlen > b.len() { return v; }
        match rtype {
            1 if rdlen == 4 =>
                v.push((name, format!("{}.{}.{}.{}", b[p], b[p+1], b[p+2], b[p+3]))),
            28 if rdlen == 16 => {
                let s = (0..8).map(|i| format!("{:x}",
                    u16::from_be_bytes([b[p + i*2], b[p + i*2 + 1]])))
                    .collect::<Vec<_>>().join(":");
                v.push((name, s));
            }
            5 => if let Some((cn, _)) = read_name(b, p) { v.push((name, format!("CNAME:{cn}"))) },
            _ => {}
        }
        p += rdlen;
    }
    v
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--chromium-check") { chromium::diagnostic().unwrap(); return; }
    if args.iter().any(|a| a == "--enrich") { enrich::run().unwrap(); return; }
    if args.iter().any(|a| a == "--sync") { sync::run().unwrap(); return; }
    if args.iter().any(|a| a == "--watch") { flow::run().unwrap(); return; }
    if args.iter().any(|a| a == "--cookies") { cookies::run().unwrap(); return; }
    if args.iter().any(|a| a == "--correlate") { correlate::run().unwrap(); return; }
    if args.iter().any(|a| a == "--app") { tui_app::run().unwrap(); return; }
    if args.iter().any(|a| a == "--tui-stream") { tui_stream::run().unwrap(); return; }
    if args.iter().any(|a| a == "--tui") { tui::run().unwrap(); return; }
    if !args.iter().any(|a| a == "--dns-tap") { eprintln!("usage: panopticon --dns-tap | --watch | --cookies"); return; }
    fs::create_dir_all("data").ok();
    let iface = datalink::interfaces().into_iter()
        .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .expect("no live interface");
    eprintln!("[panopticon] dns-tap :: {}", iface.name);
    let mut rx = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        _ => panic!("need cap_net_raw"),
    };
    let mut log = OpenOptions::new().create(true).append(true).open("data/dns.log").unwrap();
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
                println!("{val} {name}");
            }
        }
    }
}
