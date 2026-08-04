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
  Panopticon first searches by attribute for **one** item, the browser's own
  `<Product> Safe Storage` entry. If that search returns nothing — the normal case
  on KDE — it falls back to listing your keyring collections and reading the
  *labels* of the items in them to find that same entry, unlocking collections as
  it goes. It reads the secret of only the matching item; other labels are
  compared in memory and discarded. It never writes to or modifies your keyring,
  and the key it retrieves is held in memory for the life of the process only —
  never written to disk. If no keyring is reachable, affected cookies are skipped
  rather than mis-decrypted.
- **Network flows** — via eBPF, the destination IP/port of outbound connections
  (requires elevated privileges; see below).
- **DNS responses** — to map IPs back to domains.

## What it writes to disk

Almost everything Panopticon writes goes to `./data/`, which is covered by
`.gitignore`. **Treat the whole directory as sensitive.** The one exception is the
live-flow socket, described at the end of this section. Contents, in increasing
order of sensitivity:

- `cookies_detail.tsv` — cookie *names, hosts, browser, attributed company,
  first/third-party relationship, categories, entropy, and detection flags*, plus
  a 12-character truncated hash of each value. **No raw
  cookie values are written to this file.** Note that every cookie value *is* read
  and processed in memory during the enrichment pass — that is how entropy, PII
  detection and sync hashing are computed, and Chromium values are decrypted to do
  it. What gets written out is the derived metadata, not the value. In the TUI,
  values are re-read live from the browser when you open a specific cookie.
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

**Do not commit any of these files.** The only ones intended for sharing are the
*redacted* report variants, and even those list the sites you visit — read one
before you send it.

Beyond `./data/`, the live-flow daemon creates a Unix socket, at
`/run/panopticon.sock` if it can write there, otherwise `data/panopticon.sock`
(or `$PANOPTICON_SOCK`). Flow events carry the process name, PID, owning package,
destination IP, port, hostname and ASN owner — a live view of your browsing. The
socket is chowned to the project owner and set `0600`, so only that user can read
it.

## What it does NOT do

- Does not transmit your cookies, browsing history, or personal data anywhere.
  No analytics, telemetry, or "phone home" behavior.
- Two things do leave your machine, both by necessity and neither containing your
  data: the reference-data downloads you run explicitly via `fetch-data.sh`, and
  **reverse-DNS (PTR) lookups** in the Flows tab, which resolve a destination IP
  to a hostname via `getent hosts`. Those queries go to whatever resolver your
  system is configured to use, so that resolver learns which IPs you are asking
  about — the same IPs you are already connecting to. Results are cached in
  memory. Skip the Flows tab if you do not want these lookups made.
- Does not modify your cookies, browser state, or keyring. All browser reads are
  `immutable=1`; the keyring is read-only.
- Does not persist decrypted cookie values except in the two cases named above
  (`sync_clusters.tsv`, and a full PII report you explicitly export).
- Does not store or cache your keyring key on disk.

## Privileges

- **Cookie / sync / PII analysis** runs entirely as your normal user. No root needed.
- **Keyring access** uses your existing session's Secret Service. If a collection
  is locked, the *keyring daemon* (GNOME Keyring / KWallet) may show its own
  password prompt — Panopticon triggers that unlock, but never sees, handles or
  stores your password; the dialog belongs to the keyring, not to Panopticon.
  Because the fallback search walks your collections looking for the browser's
  storage entry, it can prompt for a collection unrelated to your browser. Cancel
  the prompt and the affected cookies are skipped rather than mis-decrypted.
- **Live network flow capture** (eBPF) requires three capabilities, granted by the
  unit `install-service.sh` generates: `CAP_BPF` to load the program, `CAP_PERFMON`
  to attach the kprobe, and `CAP_NET_ADMIN` for the network hook. The unit runs as
  *you*, not root, with `NoNewPrivileges`, `ProtectSystem=strict` and `ProtectHome=read-only`,
  and deliberately does **not** grant `CAP_DAC_READ_SEARCH` — that would let the
  daemon read any file on the system, and the only thing it buys is package
  attribution for other users' processes, which will show `?` instead.
  This is the only component needing elevation; the full cookie/PII analysis runs
  as a normal user without it.

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
