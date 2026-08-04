#!/usr/bin/env bash
# Build Panopticon, including the eBPF object that live flow capture needs.
#
# The eBPF program is a SEPARATE cargo workspace (crates/ebpf) targeting
# bpfel-unknown-none on nightly, so `cargo build --release` in the repo root does
# not build it. That is what this script is for.
#
#   ./build.sh          # everything (eBPF + main binary) where possible
#   ./build.sh --no-bpf # main binary only: cookies, PII, sync, reports
#
# If the eBPF toolchain is missing, this builds everything else and tells you what
# to install — a missing kernel toolchain should not stop you analysing cookies.
#
set -euo pipefail
cd "$(dirname "$0")"

BPF=1
[ "${1:-}" = "--no-bpf" ] && BPF=0

if [ "$BPF" = 1 ]; then
  echo "==> checking eBPF toolchain"
  missing=0

  if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo "    missing: nightly toolchain   ->  rustup toolchain install nightly"
    missing=1
  fi

  if ! rustup component list --toolchain nightly 2>/dev/null | grep -q '^rust-src (installed)'; then
    echo "    missing: rust-src            ->  rustup component add rust-src --toolchain nightly"
    missing=1
  fi

  # cargo invokes bpf-linker from CARGO_HOME/bin directly, so it works even when
  # that directory is not on PATH. Check both rather than PATH alone.
  cargo_bin="${CARGO_HOME:-$HOME/.cargo}/bin/bpf-linker"
  if ! command -v bpf-linker >/dev/null 2>&1 && [ ! -x "$cargo_bin" ]; then
    echo "    missing: bpf-linker          ->  cargo install bpf-linker"
    missing=1
  fi

  if [ "$missing" = 1 ]; then
    echo
    echo "    Live flow capture needs the tools above. Building everything else —"
    echo "    cookies, PII, sync and reports all work without it. Install the"
    echo "    missing tools and re-run ./build.sh to enable live capture."
    echo
    BPF=0
  else
    echo "    ok"
  fi
fi

if [ "$BPF" = 1 ]; then
  echo "==> building eBPF object (crates/ebpf)"
  ( cd crates/ebpf && cargo +nightly build --release \
      --target bpfel-unknown-none -Z build-std=core )
  obj="crates/ebpf/target/bpfel-unknown-none/release/panopticon-ebpf"
  if [ ! -f "$obj" ]; then
    echo "    expected $obj but it was not produced" >&2
    exit 1
  fi
  echo "    ok: $obj"
else
  echo "==> skipping eBPF: live flow capture will be unavailable"
fi

echo "==> building panopticon"
cargo build --release

echo
echo "Done. Next:"
echo "  ./fetch-data.sh                         # if you have not already"
echo "  ./target/release/panopticon --enrich    # analyse your cookies"
echo "  ./target/release/panopticon --app       # open the dashboard"
if [ "$BPF" = 1 ]; then
  echo "  ./install-service.sh                    # optional: live flow capture"
fi
