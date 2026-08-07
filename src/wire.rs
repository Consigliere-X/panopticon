// Shared event schema + socket path resolution for daemon<->tui streaming.
use serde::{Serialize, Deserialize};

pub const SOCK_ENV: &str = "PANOPTICON_SOCK";
// Server side: where to BIND. Prefer /run if we can create there, else project-local.
pub fn sock_bind_path() -> String {
    if let Ok(p) = std::env::var(SOCK_ENV) { return p; }
    if std::fs::OpenOptions::new().write(true).create(true).open("/run/.pano_test")
        .map(|_| { std::fs::remove_file("/run/.pano_test").ok(); true }).unwrap_or(false) {
        return "/run/panopticon.sock".into();
    }
    "data/panopticon.sock".into()
}

// Client side: CONNECT to whichever socket actually exists.
pub fn sock_path() -> String {
    if let Ok(p) = std::env::var(SOCK_ENV) { return p; }
    const CANDS: [&str; 2] = ["/run/panopticon.sock", "data/panopticon.sock"];
    // First pass: a socket we can actually CONNECT to always wins. Doing this for
    // every candidate before falling back matters — a daemon that ran as root once
    // leaves /run/panopticon.sock behind, and a stale-but-present socket file there
    // would otherwise shadow the live one the current daemon bound under data/.
    for cand in CANDS {
        if std::os::unix::net::UnixStream::connect(cand).is_ok() { return cand.into(); }
    }
    // Second pass: nothing accepted a connection. Fall back to a path that at least
    // exists as a socket, in case a probe raced the daemon's startup.
    for cand in CANDS {
        if std::fs::metadata(cand).map(|m|
            std::os::unix::fs::FileTypeExt::is_socket(&m.file_type())).unwrap_or(false) {
            return cand.into();
        }
    }
    "/run/panopticon.sock".into()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FlowEvent {
    pub comm: String,
    pub pid: u32,
    pub pkg: String,
    pub ip: String,
    pub port: u16,
    pub host: String,
    pub org: Option<String>,   // ASN-resolved owner, if known
}
