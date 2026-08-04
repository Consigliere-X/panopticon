#!/usr/bin/env bash
# Generate and install the systemd unit for live flow capture.
#
# The unit has to reference absolute paths and a user, both of which differ per
# machine — so it is generated here rather than shipped with someone else's
# home directory baked into it.
#
set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
BIN="$ROOT/target/release/panopticon"
OBJ="$ROOT/crates/ebpf/target/bpfel-unknown-none/release/panopticon-ebpf"
RUN_AS="${SUDO_USER:-$USER}"
UNIT=/etc/systemd/system/panopticon.service

[ -x "$BIN" ] || { echo "no binary at $BIN — run ./build.sh first"; exit 1; }
[ -f "$OBJ" ] || { echo "no eBPF object at $OBJ — run ./build.sh (without --no-bpf)"; exit 1; }

echo "==> installing $UNIT"
echo "    binary:  $BIN"
echo "    workdir: $ROOT"
echo "    user:    $RUN_AS"

sudo tee "$UNIT" >/dev/null <<UNITEOF
[Unit]
Description=Panopticon privacy telemetry watcher
After=network.target

[Service]
Type=simple
ExecStart=$BIN --watch
WorkingDirectory=$ROOT
User=$RUN_AS

# Least privilege: CAP_BPF loads the program, CAP_PERFMON attaches the kprobe,
# CAP_NET_ADMIN is needed for the network hook. Nothing else is granted — in
# particular NOT CAP_DAC_READ_SEARCH, which would let this read any file on the
# system. Without it, process->package attribution may show "?" for processes
# owned by other users; that is the intended trade.
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$ROOT/data
PrivateTmp=yes
RestrictSUIDSGID=yes

Restart=on-failure
Nice=10

[Install]
WantedBy=multi-user.target
UNITEOF

sudo systemctl daemon-reload
echo
echo "Installed. Start it with:"
echo "  sudo systemctl enable --now panopticon"
echo "  systemctl status panopticon"
echo
echo "Remove with:"
echo "  sudo systemctl disable --now panopticon && sudo rm $UNIT"
