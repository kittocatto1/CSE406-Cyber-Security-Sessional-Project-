#!/usr/bin/env bash
# run_attack1.sh — orchestrate Attack 1 end-to-end (report Phase 4).
# Owner: ANISA.  Expects the lab to be up (setup_namespaces.sh) + a live flow.
#
#   1. start a long-lived flow (baseline)      -> client<->server
#   2. start capture on the client             -> evidence
#   3. fire the blind reset from the attacker  -> should tear the flow down
#
# EXPECTATION (report §5):
#   - custom-5.15 kernel: connection resets  (ATTACK SUCCEEDS)
#   - stock kernel:       spoofed pkt ignored (ATTACK FAILS -> shows the defense)
set -euo pipefail
echo "[*] uname: $(uname -r)   <-- note which kernel you are on for the report"

echo "[*] (1) start victim flow"      # run baseline in background for a while
( cd ../baseline && ./run_baseline.sh 120 ) &

echo "[*] (2) start capture on client"
( cd ../baseline && sudo ./capture.sh client attack1.pcap ) &

sleep 3
echo "[*] (3) launch blind reset from attacker ns"
sudo ip netns exec attacker python3 -m attack1_reset.blind_reset

echo "[?] Check: did the client's connection drop? (ss -tan should lose it)"
# TODO(Anisa): grep `ss` output before/after and print SUCCESS/FAIL automatically.
