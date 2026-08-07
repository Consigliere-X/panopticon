//! Chromium-family cookie support (Chrome, Chromium, Brave, Edge, Vivaldi, Opera).
//!
//! Chromium encrypts cookie values on Linux. Scheme (os_crypt_linux.cc):
//!   key = PBKDF2-HMAC-SHA1(password, salt="saltysalt", iters=1, dklen=16)
//!   iv  = 16 * 0x20  ;  ct = AES-128-CBC(key, iv, PKCS7(payload))  ;  stored = prefix||ct
//!   prefix "v10" -> password = "peanuts"      (no keyring; basic storage)
//!   prefix "v11" -> password = <Secret Service "…Safe Storage" secret>
//! Chrome >= M124 prepends SHA256(host_key) to the payload before encrypting; we
//! detect-and-strip that 32-byte prefix adaptively so mixed DBs decode correctly.
//!
//! INVARIANT (matches the Firefox path): raw cookie *values* are never written to
//! disk here. `read_all` returns decrypted values in memory for the enrich pass;
//! `fetch_one` returns a single value live for the TUI. Neither persists a value.

use rusqlite::{Connection, OpenFlags};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Mutex, OnceLock},
};

use aes::Aes128;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

type Aes128CbcDec = cbc::Decryptor<Aes128>;

const SALT: &[u8] = b"saltysalt";
const IV: [u8; 16] = [0x20; 16];
// Chromium timestamps are microseconds since 1601-01-01; offset to the Unix epoch.
const WIN_EPOCH_OFFSET_SECS: i64 = 11_644_473_600;

#[derive(Clone)]
struct Keys {
    v10: [u8; 16],
    v11: Option<[u8; 16]>,
}

pub struct Store {
    pub browser: String, // display/attribution, e.g. "chrome", "brave"
    app_attr: String,    // Secret Service "application" attribute for v11 lookup
    pub path: PathBuf,   // the Cookies sqlite file
}

fn derive_key(password: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, SALT, 1, &mut key);
    key
}

/// Strip a leading 32-byte SHA256(host_key) domain-binding prefix if present
/// (Chrome M124+). Tries host_key as stored and without a leading dot.
fn strip_domain_hash(host_key: &str, plain: Vec<u8>) -> Vec<u8> {
    if plain.len() >= 32 {
        for cand in [host_key, host_key.trim_start_matches('.')] {
            if plain[..32] == Sha256::digest(cand.as_bytes())[..] {
                return plain[32..].to_vec();
            }
        }
    }
    plain
}

fn decrypt(host_key: &str, enc: &[u8], legacy_plain: &str, keys: &Keys) -> Option<String> {
    if enc.len() < 3 {
        // No ciphertext — very old Chrome stored plaintext in the `value` column.
        return Some(legacy_plain.to_string());
    }
    let (prefix, ct) = enc.split_at(3);
    let key: &[u8; 16] = match prefix {
        b"v10" => &keys.v10,
        b"v11" => keys.v11.as_ref()?, // no keyring key -> refuse (no silent garbage)
        _ => return None,             // unknown scheme (e.g. Windows DPAPI) -> skip
    };
    if ct.is_empty() || ct.len() % 16 != 0 {
        return None;
    }
    let mut buf = ct.to_vec();
    let plain = Aes128CbcDec::new(key.into(), &IV.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .ok()?
        .to_vec();
    Some(String::from_utf8_lossy(&strip_domain_hash(host_key, plain)).into_owned())
}

// ---- keyring (v11) --------------------------------------------------------

/// Fetch a browser's "Safe Storage" password from the Secret Service. Runs on a
/// dedicated thread with its own current-thread runtime so it is safe to call
/// whether or not the caller is already inside a tokio runtime. Returns None if
/// there is no session bus, no keyring, or no matching item (v11 cookies are then
/// simply skipped rather than mis-decrypted).
fn keyring_password(app: &str) -> Option<Vec<u8>> {
    let app = app.to_string();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        rt.block_on(fetch_secret(&app))
    })
    .join()
    .ok()
    .flatten()
}

/// Records why the last keyring lookup failed, per app, so `--chromium-check`
/// can report something actionable instead of a bare "not found".
static KEYRING_REASON: OnceLock<Mutex<HashMap<String, String>>> = OnceLock::new();

fn set_reason(app: &str, why: impl Into<String>) {
    let m = KEYRING_REASON.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(mut g) = m.lock() {
        g.insert(app.to_string(), why.into());
    }
}

pub fn keyring_reason(app: &str) -> Option<String> {
    let m = KEYRING_REASON.get_or_init(|| Mutex::new(HashMap::new()));
    m.lock().ok()?.get(app).cloned()
}

async fn fetch_secret(app: &str) -> Option<Vec<u8>> {
    use secret_service::{EncryptionType, SecretService};
    let ss = match SecretService::connect(EncryptionType::Dh).await {
        Ok(s) => s,
        Err(e) => {
            set_reason(
                app,
                format!(
                    "cannot reach a Secret Service on the session bus ({e}). \
                     If this is a KDE/KWallet session, Chromium stored the key in \
                     KWallet, not libsecret — see --password-store below."
                ),
            );
            return None;
        }
    };
    // Chromium registers under the v2 (then legacy v1) schema with application=<product>.
    let searches = [
        HashMap::from([
            ("xdg:schema", "chrome_libsecret_os_crypt_password_v2"),
            ("application", app),
        ]),
        HashMap::from([
            ("xdg:schema", "chrome_libsecret_os_crypt_password_v1"),
            ("application", app),
        ]),
        HashMap::from([("xdg:schema", "chrome_libsecret_os_crypt_password")]),
        HashMap::from([("application", app)]),
    ];
    for attrs in searches {
        if let Ok(res) = ss.search_items(attrs).await {
            // Prefer already-unlocked items; fall back to locked ones (unlocked below).
            let mut items = res.unlocked;
            items.extend(res.locked);
            if let Some(item) = items.into_iter().next() {
                let _ = item.unlock().await; // no-op if already unlocked
                if let Ok(secret) = item.get_secret().await {
                    if !secret.is_empty() {
                        return Some(secret);
                    }
                }
            }
        }
    }
    // Attribute search failed — sweep every collection for the well-known label
    // ("Chromium Safe Storage" / "Chrome Safe Storage"), which survives attribute
    // schema drift between Chromium versions.
    let mut seen_any = false;
    if let Ok(colls) = ss.get_all_collections().await {
        for coll in colls {
            let _ = coll.unlock().await;
            if let Ok(items) = coll.get_all_items().await {
                for item in items {
                    seen_any = true;
                    let label = item.get_label().await.unwrap_or_default().to_lowercase();
                    if label.contains("safe storage") && label.contains(&app.to_lowercase()) {
                        let _ = item.unlock().await;
                        if let Ok(secret) = item.get_secret().await {
                            if !secret.is_empty() {
                                return Some(secret);
                            }
                        }
                    }
                }
            }
        }
    }
    set_reason(
        app,
        if seen_any {
            format!(
                "connected to the keyring, but no \"{app} Safe Storage\" item was found. \
                 If this is a KDE/KWallet session the key lives in KWallet instead."
            )
        } else {
            "connected to the keyring, but it exposed no items (locked collection, \
             or a different keyring than the one Chromium wrote to)."
                .to_string()
        },
    );
    None
}

/// Per-application key set, derived once and cached (keyring hit at most once).
fn keys_for(app_attr: &str) -> Keys {
    static CACHE: OnceLock<Mutex<HashMap<String, Keys>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(k) = cache.lock().unwrap().get(app_attr) {
        return k.clone();
    }
    let keys = Keys {
        v10: derive_key(b"peanuts"),
        v11: keyring_password(app_attr).map(|pw| derive_key(&pw)),
    };
    cache
        .lock()
        .unwrap()
        .insert(app_attr.to_string(), keys.clone());
    keys
}

// ---- store discovery ------------------------------------------------------

// Browser config dirs, relative to a config root (see `config_roots`).
// (relative dir, browser label, Secret Service "application" attribute for v11)
const BROWSERS: &[(&str, &str, &str)] = &[
    ("google-chrome", "chrome", "chrome"),
    ("google-chrome-beta", "chrome-beta", "chrome"),
    ("google-chrome-unstable", "chrome-dev", "chrome"),
    ("chromium", "chromium", "chromium"),
    ("BraveSoftware/Brave-Browser", "brave", "brave"),
    ("BraveSoftware/Brave-Browser-Beta", "brave-beta", "brave"),
    ("microsoft-edge", "edge", "microsoft-edge"),
    ("microsoft-edge-beta", "edge-beta", "microsoft-edge"),
    ("microsoft-edge-dev", "edge-dev", "microsoft-edge"),
    ("vivaldi", "vivaldi", "vivaldi"),
    ("opera", "opera", "opera"),
];

/// Base directories that may contain the browser dirs above. Covers native
/// installs (`$XDG_CONFIG_HOME` or `~/.config`) plus Flatpak (`~/.var/app/<id>/
/// config`) and Snap (`~/snap/<id>/current|common/.config`), since those package
/// formats relocate the whole profile out of `~/.config`.
fn config_roots() -> Vec<PathBuf> {
    let home = match std::env::var("HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => return vec![],
    };
    let mut roots = vec![];
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) if !x.is_empty() => roots.push(PathBuf::from(x)),
        _ => roots.push(home.join(".config")),
    }
    if let Ok(rd) = std::fs::read_dir(home.join(".var/app")) {
        for e in rd.flatten() {
            roots.push(e.path().join("config"));
        }
    }
    if let Ok(rd) = std::fs::read_dir(home.join("snap")) {
        for e in rd.flatten() {
            roots.push(e.path().join("current/.config"));
            roots.push(e.path().join("common/.config"));
        }
    }
    roots
}

fn is_sqlite(path: &std::path::Path) -> bool {
    use std::io::Read;
    let mut hdr = [0u8; 16];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut hdr))
        .map(|_| &hdr[..15] == b"SQLite format 3")
        .unwrap_or(false)
}

pub fn find_stores() -> Vec<Store> {
    let mut out = vec![];
    let mut seen = std::collections::HashSet::new();
    for root in config_roots() {
        for &(rel, browser, app) in BROWSERS {
            let base = root.join(rel);
            if !base.exists() {
                continue;
            }
            // Cookies lives at <profile>/Cookies or <profile>/Network/Cookies.
            for e in walkdir::WalkDir::new(&base)
                .max_depth(4)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let p = e.path();
                if p.file_name().and_then(|n| n.to_str()) == Some("Cookies")
                    && is_sqlite(p)
                    && seen.insert(p.to_path_buf())
                {
                    // Qualify the label with the profile directory when it is not the
                    // default one, so "chromium" and "chromium:Profile 1" stay distinct.
                    // Without this, two profiles of the same browser are indistinguishable
                    // in the UI and a live value lookup returns whichever profile is
                    // found first.
                    let mut prof = p.parent();
                    if prof.and_then(|d| d.file_name()).and_then(|n| n.to_str()) == Some("Network") {
                        prof = prof.and_then(|d| d.parent());
                    }
                    let pname = prof
                        .and_then(|d| d.file_name())
                        .and_then(|n| n.to_str())
                        .unwrap_or("Default");
                    let label = if pname == "Default" || pname == browser {
                        browser.to_string()
                    } else {
                        format!("{browser}:{pname}")
                    };
                    out.push(Store {
                        browser: label,
                        app_attr: app.into(),
                        path: p.to_path_buf(),
                    });
                }
            }
        }
    }
    out
}

fn chromium_expiry_to_unix(micros: i64) -> i64 {
    if micros <= 0 {
        0 // session cookie
    } else {
        (micros / 1_000_000 - WIN_EPOCH_OFFSET_SECS).max(0)
    }
}

fn open_ro(path: &std::path::Path) -> Option<Connection> {
    let uri = format!("file:{}?immutable=1", path.display());
    Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .ok()
}

/// Decrypt every Chromium cookie across all discovered stores. Returns rows in
/// the SAME shape as the Firefox reader plus the source browser label:
/// (host, name, value, unix_expiry, samesite, browser).
/// Undecryptable rows (unknown scheme, or v11 with no keyring) are skipped.
pub fn read_all() -> Vec<(String, String, String, i64, i32, String)> {
    let mut out = vec![];
    for store in find_stores() {
        let keys = keys_for(&store.app_attr);
        let conn = match open_ro(&store.path) {
            Some(c) => c,
            None => continue,
        };
        let mut q = match conn.prepare(
            "SELECT host_key, name, value, encrypted_value, expires_utc, samesite FROM cookies",
        ) {
            Ok(q) => q,
            Err(_) => continue,
        };
        let rows = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2).unwrap_or_default(),
                    r.get::<_, Vec<u8>>(3).unwrap_or_default(),
                    r.get::<_, i64>(4).unwrap_or(0),
                    r.get::<_, i32>(5).unwrap_or(-1),
                ))
            })
            .map(|it| it.filter_map(|x| x.ok()).collect::<Vec<_>>())
            .unwrap_or_default();
        for (host, name, legacy, enc, exp, ss) in rows {
            if let Some(value) = decrypt(&host, &enc, &legacy, &keys) {
                out.push((
                    host,
                    name,
                    value,
                    chromium_expiry_to_unix(exp),
                    ss,
                    store.browser.clone(),
                ));
            }
        }
    }
    out
}

/// Live single-value fetch for the TUI. `browser` selects which store to read
/// (matching the label from `read_all`), so a cookie present in several browsers
/// resolves to the value from *its own* browser. Never persists.
pub fn fetch_one(browser: &str, host: &str, name: &str) -> Option<String> {
    for store in find_stores() {
        if !browser.is_empty() && store.browser != browser {
            continue;
        }
        let conn = match open_ro(&store.path) {
            Some(c) => c,
            None => continue,
        };
        let row = conn.query_row(
            "SELECT value, encrypted_value FROM cookies WHERE host_key=?1 AND name=?2 LIMIT 1",
            rusqlite::params![host, name],
            |r| {
                Ok((
                    r.get::<_, String>(0).unwrap_or_default(),
                    r.get::<_, Vec<u8>>(1).unwrap_or_default(),
                ))
            },
        );
        if let Ok((legacy, enc)) = row {
            let keys = keys_for(&store.app_attr);
            if let Some(v) = decrypt(host, &enc, &legacy, &keys) {
                return Some(v);
            }
        }
    }
    None
}

/// `--chromium-check`: prove decryption against the user's real cookies without
/// writing any value to disk. Prints per-store variant counts and masked samples.
pub fn diagnostic() -> anyhow::Result<()> {
    let stores = find_stores();
    if stores.is_empty() {
        println!(
            "[chromium] no Chromium-family cookie stores found \
             (searched ~/.config, Flatpak ~/.var/app, and Snap ~/snap)"
        );
        return Ok(());
    }
    for store in &stores {
        let keys = keys_for(&store.app_attr);
        let has_v11 = keys.v11.is_some();
        println!(
            "\n[{}] {}\n  keyring(v11) key: {}",
            store.browser,
            store.path.display(),
            if has_v11 {
                "found".to_string()
            } else {
                format!(
                    "NOT found (v11 cookies will be skipped)\n  reason: {}",
                    keyring_reason(&store.app_attr)
                        .unwrap_or_else(|| "unknown".to_string())
                )
            }
        );
        let conn = match open_ro(&store.path) {
            Some(c) => c,
            None => {
                println!("  could not open (locked by a running browser? close it and retry)");
                continue;
            }
        };
        let mut q = conn.prepare(
            "SELECT host_key, name, value, encrypted_value FROM cookies",
        )?;
        let rows: Vec<(String, String, String, Vec<u8>)> = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2).unwrap_or_default(),
                    r.get::<_, Vec<u8>>(3).unwrap_or_default(),
                ))
            })?
            .filter_map(|x| x.ok())
            .collect();
        let (mut v10, mut v11, mut plain, mut other, mut ok, mut fail) = (0, 0, 0, 0, 0, 0);
        let mut samples = 0;
        for (host, name, legacy, enc) in &rows {
            match enc.get(..3) {
                Some(b"v10") => v10 += 1,
                Some(b"v11") => v11 += 1,
                _ if enc.len() < 3 => plain += 1,
                _ => other += 1,
            }
            match decrypt(host, enc, legacy, &keys) {
                Some(v) => {
                    ok += 1;
                    if samples < 3 && !v.is_empty() {
                        let mask: String = v.chars().take(3).collect();
                        println!("  ok  {host} / {name}  -> {} chars  [{mask}…]", v.chars().count());
                        samples += 1;
                    }
                }
                None => fail += 1,
            }
        }
        println!(
            "  total={} decrypted={} skipped={} | v10={v10} v11={v11} plaintext={plain} other={other}",
            rows.len(),
            ok,
            fail
        );
    }
    println!("\n[chromium] done. Values shown masked; nothing was written to disk.");
    Ok(())
}
