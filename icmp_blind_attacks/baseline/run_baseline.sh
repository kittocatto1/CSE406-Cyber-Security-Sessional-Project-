#!/usr/bin/env bash
# ===========================================================================
# run_baseline.sh — start the victim TCP flow + record "before attack" numbers
# Owner: ANISA  (report Phase 2)
#
# We need a long-lived, high-throughput flow so the attacks have something to
# hit, and a baseline to compare against. iperf3: server in the server ns,
# client in the client ns.
# ===========================================================================
set -euo pipefail
DUR=${1:-60}          # seconds to run (default 60)

echo "[*] Starting iperf3 server in the server namespace..."
ip netns exec server iperf3 -s -1 &     # -1 = handle one connection then exit
sleep 1

echo "[*] Starting $DUR s baseline transfer from the client namespace..."
# -t DUR  : duration ;  save the reported throughput for the report graphs
ip netns exec client iperf3 -c 10.0.0.2 -t "$DUR" | tee baseline_result.txt

echo "[+] Baseline saved to baseline_result.txt (use this as the 'before' bar)."
# TODO(Anisa): also snapshot `ss -ti` on the client mid-transfer to record the
# healthy cwnd / MSS / retransmit counts for the before/after comparison.
