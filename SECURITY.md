# Panopticon — Data Handling & Security

Panopticon is a local privacy-analysis tool. It inspects data that is **already
on your machine** and shows you what trackers collect. It is designed so that
your sensitive data never leaves your control.

## What it reads

- **Browser cookies** — read-only, from Firefox's `cookies.sqlite` and from
  Chromium-family browsers' `Cookies` database (Chrome, Chromium, Brave, Edge,
  Vivaldi, Opera; native, Flatpak, or Snap installs). Every database is opened
  with `immutable=1`. Panopticon never writes to your browser's database.
- **Your desktop keyring** — Chromium encrypts cookie values with a key held in
  the Secret Service (GNOME Keyring, or KWallet via a compatibility bridge).
  Panopticon requests **one** item, the browser's own `<Product> Safe Storage`
  entry, purely to decrypt that browser's cookies. It never writes to or modifies
  your keyring, and the key is held in memory for the life of the process only —
  never written to disk. If no keyring is reachable, affected cookies are skipped
  rather than mis-decrypted.
- **Network flows** — via eBPF, the destination IP/port of outbound connections
  (requires elevated privileges; see below).
- **DNS responses** — to map IPs back to domains.

## What it writes to disk

Everything Panopticon writes goes to `./data/`, which is covered by `.gitignore`.
**Treat the whole directory as sensitive.** Contents, in increasing order of
sensitivity:

- `cookies_detail.tsv` — cookie *names, hosts, browser, categories, entropy, and
  detection flags*, plus a 12-character truncated hash of each value. **No raw
  cookie values.** Full values are read live from the browser database only at
  the moment you view a specific cookie, held in memory, and never persisted.
- `dns.log`, `flows.log` — your resolved domains and outbound connections. This
  is effectively your **browsing history**. It stays local.
- `sync_clusters.tsv` — for cookies whose value appears on two or more sites,
  this records **the full shared value**, because that shared identifier is the
  evidence of cross-site tracking and is what the Sync Graph displays. Such
  values are tracking IDs by nature, but a shared value can still be a session
  token. Treat this file as credential-grade.
- `reports/` — reports you export with `e`. The *redacted* variants mask values
  and are meant to be shareable. The `*_pii_full.md` variant contains **decoded
  personal data in the clear** (email, name, location, device IDs) by design, so
  you can see exactly what a site holds. It is written `chmod 600`, is never
  produced unless you explicitly choose the full variant, and should not be
  shared or committed.

**None of these files should ever be committed or shared.**

## What it does NOT do

- Does not transmit anything off your machine. No analytics, telemetry, or
  "phone home" behavior — network access is limited to the reference-data
  downloads you run explicitly via `fetch-data.sh`.
- Does not modify your cookies, browser state, or keyring. All browser reads are
  `immutable=1`; the keyring is read-only.
- Does not persist decrypted cookie values except in the two cases named above
  (`sync_clusters.tsv`, and a full PII report you explicitly export).
- Does not store or cache your keyring key on disk.

## Privileges

- **Cookie / sync / PII analysis** runs entirely as your normal user. No root needed.
- **Keyring access** uses your existing session's Secret Service. Your keyring
  must be unlocked; Panopticon does not prompt for or handle your password.
- **Live network flow capture** (eBPF) requires `CAP_BPF` / `CAP_NET_ADMIN`, granted
  via the systemd unit or `setcap`. This is the only component needing elevation.
  You can run the full cookie/PII analysis without it.

## Your responsibility

The `./data/` directory reflects your real browsing and cookie contents. Treat it
as sensitive. Do not run Panopticon on a shared account where others can read your
home directory, and do not commit the `data/` folder.

Screenshots and exported reports can leak too: a cookie list shows the sites you
visit, and a decoded value can contain a live session identifier. Check before
posting either.

## Reporting

This is a personal/research tool provided as-is with no warranty. Review the source
before running — especially the eBPF component, which runs in kernel space.
