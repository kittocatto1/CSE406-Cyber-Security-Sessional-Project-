#!/usr/bin/env bash
# capture.sh — packet capture + connection-state logging helper.
# Owner: ANISA. Call this alongside any attack to gather evidence (Phase 6).
#
# Usage:  sudo ./capture.sh <namespace> <outfile.pcap>
# Example: sudo ./capture.sh client attack1.pcap
set -euo pipefail
NS=${1:-client}
OUT=${2:-capture.pcap}

echo "[*] tcpdump in ns=$NS -> $OUT  (Ctrl-C to stop)"
# Capture ICMP + the victim TCP port so the pcap shows the spoofed packet
# arriving right when the connection changes state.
ip netns exec "$NS" tcpdump -i any -w "$OUT" 'icmp or tcp port 5201'

# TODO(Anisa): in a second terminal, loop `ss -tan` / `ss -ti` in the same ns
# every 0.5s into a log so we can timestamp the exact moment of teardown /
# throughput drop. This is the evidence for report deliverable (c).
