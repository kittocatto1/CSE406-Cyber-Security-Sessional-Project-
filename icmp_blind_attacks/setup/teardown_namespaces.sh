#!/usr/bin/env bash
# teardown_namespaces.sh — remove everything setup_namespaces.sh created.
# Owner: ANISA.  Run as root:  sudo ./teardown_namespaces.sh
set -uo pipefail
for ns in client server attacker; do
    ip netns del "$ns" 2>/dev/null || true    # veth pairs die with the ns
done
ip link del br-lab 2>/dev/null || true
echo "[+] Lab torn down."
