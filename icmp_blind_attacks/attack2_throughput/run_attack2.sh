#!/usr/bin/env bash
# run_attack2.sh — orchestrate Attack 2 (throughput reduction), Phase 5.
# Owner: DEBASHRI.  Runs on the STOCK kernel; flow must stay ALIVE throughout.
#
#   1. start victim flow + capture
#   2. sample `ss -ti` on the client to log cwnd/MSS over time
#   3. fire PMTU attack (2a); optionally Source Quench (2b)
#   4. compare throughput vs baseline_result.txt
set -euo pipefail
VECTOR=${1:-pmtu}        # "pmtu" (2a) or "quench" (2b)

echo "[*] (1) start victim flow"
( cd ../baseline && ./run_baseline.sh 120 ) &
( cd ../baseline && sudo ./capture.sh client attack2.pcap ) &

echo "[*] (2) sampling client TCP info -> ss_timeline.log"
( for i in $(seq 1 120); do
      echo "== t=$i =="; ip netns exec client ss -ti dst 10.0.0.2;
      sleep 1; done > ss_timeline.log ) &

sleep 3
echo "[*] (3) launch Attack 2 vector: $VECTOR"
if [ "$VECTOR" = "quench" ]; then
    sudo ip netns exec attacker python3 -m attack2_throughput.source_quench
else
    sudo ip netns exec attacker python3 -m attack2_throughput.pmtu_attack
fi

echo "[?] (4) Compare the attack-window throughput to baseline_result.txt"
# TODO(Debashri): feed attack2.pcap + ss_timeline.log to analysis/ for the graph.
