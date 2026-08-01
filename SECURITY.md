# Panopticon — Data Handling & Security

Panopticon is a local privacy-analysis tool. It inspects data that is **already
on your machine** and shows you what trackers collect. It is designed so that
your sensitive data never leaves your control.

## What it reads

- **Browser cookies** — read-only, from your Firefox `cookies.sqlite`. Panopticon
  never writes to your browser's database.
- **Network flows** — via eBPF, the destination IP/port of outbound connections
  (requires elevated privileges; see below).
- **DNS responses** — to map IPs back to domains.

## What it writes to disk

Panopticon writes only **non-sensitive metadata** to `./data/`:

- `cookies_detail.tsv` — cookie *names, hosts, categories, entropy, and detection
  flags*. **Raw cookie values are NOT written to disk.** Values that may contain
  personal data (name, email, payment info, location) are read **live from your
  browser database only at the moment you view a specific cookie**, held in memory,
  and never persisted.
- `dns.log`, `flows.log` — your resolved domains and outbound connections. This is
  effectively your **browsing history**. It stays local.

**None of these files should ever be committed or shared.** They are covered by
`.gitignore`.

## What it does NOT do

- Does not transmit anything off your machine.
- Does not write raw cookie values, decoded PII, or payment data to disk.
- Does not modify your cookies or browser state (all reads are `immutable=1`).
- Does not include analytics, telemetry, or "phone home" behavior.

## Privileges

- **Cookie / sync / PII analysis** runs entirely as your normal user. No root needed.
- **Live network flow capture** (eBPF) requires `CAP_BPF` / `CAP_NET_ADMIN`, granted
  via the systemd unit or `setcap`. This is the only component needing elevation.
  You can run the full cookie/PII analysis without it.

## Your responsibility

The `./data/` directory reflects your real browsing and cookie contents. Treat it
as sensitive. Do not run Panopticon on a shared account where others can read your
home directory, and do not commit the `data/` folder.

## Reporting

This is a personal/research tool provided as-is with no warranty. Review the source
before running — especially the eBPF component, which runs in kernel space.
