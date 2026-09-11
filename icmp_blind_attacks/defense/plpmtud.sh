#!/usr/bin/env bash
# plpmtud.sh — STRETCH defense for Attack 2a (report §6, RFC 4821).
# Owner: DEBASHRI (only if time permits — not the guaranteed deliverable).
#
# PLPMTUD stops trusting ICMP entirely: TCP probes the path with real data
# segments instead. Enable via a single sysctl and re-test.
set -euo pipefail
echo "[*] Enabling TCP MTU probing (PLPMTUD) in the client namespace..."
ip netns exec client sysctl -w net.ipv4.tcp_mtu_probing=1

echo "[+] Re-run Attack 2a: spoofed Frag-Needed should now be ignored."
# TODO(Debashri): also verify a LEGITIMATE PMTU change is still detected, so
# we prove the defense didn't break real path-MTU discovery (report §6).
