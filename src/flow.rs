fn ipport_ip(s:&str)->String{ s.rsplit_once(':').map(|(i,_)|i.to_string()).unwrap_or(s.to_string()) }
use aya::{maps::RingBuf, programs::KProbe, Ebpf};
use std::{collections::HashMap, fs, net::{Ipv4Addr, Ipv6Addr},
          process::Command, thread, time::Duration};

#[repr(C)]
#[derive(Clone, Copy)]
struct ConnEvent { pid: u32, af: u16, port: u16, addr: [u8; 16], comm: [u8; 16] }

fn dns_cache() -> HashMap<String, String> {
    fs::read_to_string("data/dns.log").unwrap_or_default().lines()
        .filter_map(|l| l.split_once(' '))
        .map(|(ip, n)| (ip.to_string(), n.to_string())).collect()
}

fn package_of(exe: &str, c: &mut HashMap<String, String>) -> String {
    if let Some(p) = c.get(exe) { return p.clone(); }
    // Ask whichever package manager this distro has. Panopticon itself is
    // distro-agnostic; only this attribution step is, so an unknown distro
    // degrades to "unpackaged" rather than failing.
    let probes: [(&str, &[&str]); 5] = [
        ("pacman", &["-Qoq"]),                  // Arch
        ("dpkg",   &["-S"]),                    // Debian/Ubuntu
        ("rpm",    &["-qf", "--queryformat", "%{NAME}"]), // Fedora/RHEL/SUSE
        ("apk",    &["info", "--who-owns"]),    // Alpine
        ("xbps-query", &["-o"]),                // Void
    ];
    let mut pkg = String::new();
    for (bin, args) in probes {
        let out = Command::new(bin).args(args).arg(exe).output();
        if let Ok(o) = out {
            if o.status.success() {
                let t = String::from_utf8_lossy(&o.stdout);
                // dpkg -S prints "pkg: /path"; apk prints "/path is owned by pkg-1.2"
                let t = t.split(':').next().unwrap_or("")
                    .rsplit(" is owned by ").next().unwrap_or("")
                    .trim().to_string();
                if !t.is_empty() { pkg = t; break; }
            }
        }
    }
    let pkg = if pkg.is_empty() { "unpackaged".to_string() } else { pkg };
    c.insert(exe.into(), pkg.clone()); pkg
}

pub fn run() -> anyhow::Result<()> {
    // start the DNS tap in a thread so flows can resolve hostnames
    std::thread::spawn(|| crate::dns::dns_tap_loop());
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || { let _ = crate::server::run_server(rx); });
    fs::create_dir_all("data").ok();
    let obj = "crates/ebpf/target/bpfel-unknown-none/release/panopticon-ebpf";
    let mut bpf = Ebpf::load(&fs::read(obj).map_err(|e| anyhow::anyhow!(
        "cannot read the eBPF object at {obj} ({e}).\n\
         The eBPF program is a separate cargo workspace and is NOT built by\n\
         `cargo build --release` in the repo root. Build it with:\n\
         \n    ./build.sh\n\n\
         Everything except live flow capture works without it."))?)?;
    let prog: &mut KProbe = bpf.program_mut("sock_connect").unwrap().try_into()?;
    prog.load()?;
    let hook = ["security_socket_connect", "tcp_v4_connect"].iter()
        .find(|h| prog.attach(**h, 0).is_ok())
        .ok_or_else(|| anyhow::anyhow!("no attachable hook"))?;
    eprintln!("[panopticon] attached :: {hook}");

    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut dns = dns_cache();
    let mut pkgs = HashMap::new();
    let _log = fs::OpenOptions::new().create(true).append(true).open("data/flows.log")?;
    let sz = std::mem::size_of::<ConnEvent>();

    loop {
        let mut got = false;
        while let Some(item) = ring.next() {
            got = true;
            let b: &[u8] = &item;
            if b.len() < sz { continue; }
            let c: ConnEvent = unsafe { std::ptr::read_unaligned(b.as_ptr() as *const _) };
            let ip = if c.af == 2 {
                Ipv4Addr::new(c.addr[0], c.addr[1], c.addr[2], c.addr[3]).to_string()
            } else {
                let mut o = [0u8; 16]; o.copy_from_slice(&c.addr);
                Ipv6Addr::from(o).to_string()
            };
            if ip.starts_with("127.") || ip == "::1" || ip == "0.0.0.0" { continue; }
            let exe = fs::read_link(format!("/proc/{}/exe", c.pid))
                .map(|p| p.display().to_string()).unwrap_or_else(|_| "<gone>".into());
            let comm = String::from_utf8_lossy(&c.comm).trim_end_matches('\0').to_string();
            if comm=="getent" || comm=="isc-net-0000" || comm.starts_with("DNS Res")
               || comm.contains("resolver") { continue; }  // reverse-DNS + resolver noise
            if !dns.contains_key(&ip) { dns = dns_cache(); }
            let host = dns.get(&ip).cloned().unwrap_or_else(|| "?".into());
            let line = format!("{comm}\tpid={}\tpkg={}\t{ip}:{}\t{host}",
                c.pid, package_of(&exe, &mut pkgs), c.port);
            println!("{line}");
            let ip_only = ipport_ip(&format!("{ip}:{}", c.port));
            let _ = tx.send((comm.clone(), c.pid, package_of(&exe,&mut pkgs),
                             ip_only, c.port, host.clone()));
        }
        if !got { thread::sleep(Duration::from_millis(50)); }
    }
}
