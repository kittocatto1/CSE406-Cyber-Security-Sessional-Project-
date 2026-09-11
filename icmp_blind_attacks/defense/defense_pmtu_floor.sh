#!/usr/bin/env bash
# ===========================================================================
# defense_pmtu_floor.sh — Defense for Attack 2a (report §6, Phase 7).
# Owner: DEBASHRI
#
# The Client refuses to accept a spoofed PMTU below a floor. One sysctl:
#   net.ipv4.route.min_pmtu   default 552  ->  raise to 1200.
# Then the forged MTU=68 from pmtu_attack.py is clamped and can't hurt us.
# This is the GUARANTEED deliverable.
# ===========================================================================
set -euo pipefail
FLOOR=${1:-1200}       # matches config.PMTU_FLOOR

echo "[*] Before:"; ip netns exec client sysctl net.ipv4.route.min_pmtu
echo "[*] Setting min_pmtu floor to $FLOOR in the client namespace..."
ip netns exec client sysctl -w net.ipv4.route.min_pmtu="$FLOOR"

echo "[+] Now re-run Attack 2a and compare throughput to the undefended run:"
echo "    sudo ip netns exec attacker python3 -m attack2_throughput.pmtu_attack"
# EXPECT: throughput no longer collapses because MTU=68 is refused.
# Known limitation (report §6): attacker can still spoof MTU=1201 for a
# milder reduction — the root problem (trusting unauthenticated ICMP) remains.
