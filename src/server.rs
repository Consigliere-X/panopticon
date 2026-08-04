use crate::wire::FlowEvent;
use std::collections::HashMap as RevCache;

// PTR reverse-DNS lookup with an in-memory cache. Fills hostnames that
// encrypted forward-DNS (DoH) hides. Uses the system resolver.
fn reverse_dns(ip: &str, cache: &Mutex<RevCache<String,String>>) -> Option<String> {
    if let Some(hit)=cache.lock().unwrap().get(ip){ 
        return if hit.is_empty(){None}else{Some(hit.clone())};
    }
    // getnameinfo via std: resolve the socket addr back to a host
    use std::net::IpAddr;
    let parsed: Option<IpAddr> = ip.parse().ok();
    let name = parsed.and_then(|_addr|{
        // dns_lookup crate would be cleaner; use a shell to `getent hosts` as a portable PTR
        std::process::Command::new("timeout").args(["1","getent","hosts", ip]).output().ok()
            .filter(|o|o.status.success())
            .and_then(|o|{
                let s=String::from_utf8_lossy(&o.stdout);
                s.split_whitespace().nth(1)
                    .filter(|h| h.chars().all(|c| c.is_ascii_alphanumeric()||c=='.'||c=='-'))
                    .filter(|h| h.contains('.') && h.len()>=4)
                    .map(|h|h.to_string())
            })
            .filter(|h| h!=ip && h.contains('.'))
    });
    cache.lock().unwrap().insert(ip.to_string(), name.clone().unwrap_or_default());
    name
}
use std::{fs, io::Write,
          os::unix::net::{UnixListener, UnixStream}, sync::{Arc, Mutex}, thread};

type Clients = Arc<Mutex<Vec<UnixStream>>>;

// ASN loading moved to crate::asn::AsnDb
fn parent(o: &str) -> &str {
    let l=o.to_lowercase();
    if l.contains("google"){"Google"} else if l.contains("meta")||l.contains("facebook"){"Meta"}
    else if l.contains("microsoft"){"Microsoft"} else if l.contains("amazon"){"Amazon"}
    else if l.contains("cloudflare"){"Cloudflare"} else if l.contains("fastly"){"Fastly"}
    else if l.contains("segment")||l.contains("twilio"){"Twilio"} else {o}
}
// asn lookup moved to AsnDb::lookup

// accept loop: register each new TUI connection
fn accept_loop(listener: UnixListener, clients: Clients) {
    for stream in listener.incoming().flatten() {
        clients.lock().unwrap().push(stream);
    }
}

// broadcast one event to all clients; drop dead ones
fn broadcast(clients: &Clients, ev: &FlowEvent) {
    let line = match serde_json::to_string(ev) { Ok(s)=>s+"\n", Err(_)=>return };
    let mut c = clients.lock().unwrap();
    c.retain_mut(|s| s.write_all(line.as_bytes()).and_then(|_| s.flush()).is_ok());
}

pub fn run_server(rx: std::sync::mpsc::Receiver<(String,u32,String,String,u16,String)>) -> anyhow::Result<()> {
    let path = crate::wire::sock_bind_path();
    let _ = fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    // The daemon may run as root (it needs CAP_BPF) while the TUI runs as you.
    // Rather than make the socket world-accessible, hand it to the user who owns
    // the project directory and lock it to them: flow events name the processes,
    // IPs and hostnames you connect to, so any other local user reading this
    // socket would be watching your browsing in real time.
    {
        use std::os::unix::fs::MetadataExt;
        let owner = fs::metadata(".").ok().map(|m| (m.uid(), m.gid()));
        if let Some((uid, gid)) = owner {
            let _ = std::os::unix::fs::chown(&path, Some(uid), Some(gid));
        }
        fs::set_permissions(
            &path,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .ok();
    }
    eprintln!("[panopticon] streaming on {path}");
    let clients: Clients = Arc::new(Mutex::new(vec![]));
    { let (l,c)=(listener, clients.clone()); thread::spawn(move || accept_loop(l, c)); }

    let asn_db = crate::asn::AsnDb::load();
    let rev_cache: Mutex<RevCache<String,String>> = Mutex::new(RevCache::new());
    let mut log = fs::OpenOptions::new().create(true).append(true).open("data/flows.log")?;
    for (comm, pid, pkg, ip, port, host) in rx {
        let org = asn_db.lookup(&ip);
        // if forward DNS didn't give a host (DoH), try reverse PTR lookup
        let host = if host=="?" || host.is_empty() {
            reverse_dns(&ip, &rev_cache).unwrap_or_else(||"?".into())
        } else { host };
        let ev = FlowEvent { comm, pid, pkg, ip, port, host, org };
        // still persist to flows.log (sync/correlate batch tools read it)
        writeln!(log, "{}\tpid={}\tpkg={}\t{}:{}\t{}",
            ev.comm, ev.pid, ev.pkg, ev.ip, ev.port, ev.host).ok();
        log.flush().ok();
        broadcast(&clients, &ev);
    }
    Ok(())
}
