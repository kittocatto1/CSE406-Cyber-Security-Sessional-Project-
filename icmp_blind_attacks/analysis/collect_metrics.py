"""
collect_metrics.py  —  Turn raw logs into tidy numbers (report Phase 6).
Owner: DEBASHRI

Inputs we produced during the runs:
  - baseline_result.txt   (iperf3 throughput, "before")
  - ss_timeline.log       (cwnd / MSS / retransmits over time, during attack)
  - *.pcap                (packet evidence)

Output: a small CSV the plotting script can read. Keep parsing dumb + readable.
"""

import re, csv


def parse_ss_timeline(path="ss_timeline.log"):
    """Pull (t, cwnd, mss, retrans) out of the `ss -ti` samples."""
    rows = []
    t = None
    for line in open(path):
        m = re.match(r"== t=(\d+) ==", line)
        if m:
            t = int(m.group(1)); continue
        # ss prints e.g. "... cwnd:10 ... mss:1448 ... retrans:0/3 ..."
        cwnd = _grab(line, r"cwnd:(\d+)")
        mss  = _grab(line, r"mss:(\d+)")
        if cwnd or mss:
            rows.append({"t": t, "cwnd": cwnd, "mss": mss})
    return rows


def _grab(line, pattern):
    m = re.search(pattern, line)
    return int(m.group(1)) if m else None


def write_csv(rows, out="metrics.csv"):
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["t", "cwnd", "mss"])
        w.writeheader(); w.writerows(rows)
    print(f"[+] wrote {out} ({len(rows)} rows)")


if __name__ == "__main__":
    write_csv(parse_ss_timeline())
    # TODO(Debashri): also parse baseline_result.txt for the single "before"
    # throughput number, and (optional) count retransmits from the pcap.
