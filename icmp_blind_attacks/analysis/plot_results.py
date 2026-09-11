"""
plot_results.py  —  Graphs for the final report (deliverables a, b, c).
Owner: DEBASHRI

Two figures the report asks for:
  1. Throughput before vs. during attack (shows Attack 2 degradation).
  2. MSS / cwnd over time (shows PMTU shrink / cwnd cut as it happens).

Also (optional) the success-probability vs. packet-count curve for Attack 1
(RFC 5927 §5-6) if you record attempts-until-success across several runs.
"""

import csv
import matplotlib.pyplot as plt


def plot_mss_over_time(csv_path="metrics.csv"):
    t, mss = [], []
    for row in csv.DictReader(open(csv_path)):
        if row["mss"]:
            t.append(int(row["t"])); mss.append(int(row["mss"]))
    plt.plot(t, mss, marker="o")
    plt.axvline(3, ls="--", label="attack starts")   # attack began ~t=3s
    plt.xlabel("time (s)"); plt.ylabel("MSS (bytes)")
    plt.title("Attack 2a: MSS collapse after spoofed PMTU")
    plt.legend(); plt.savefig("mss_over_time.png", dpi=150)
    print("[+] saved mss_over_time.png")


if __name__ == "__main__":
    plot_mss_over_time()
    # TODO(Debashri): add throughput bar chart (baseline vs attack vs defended)
    # so one figure shows attack works AND the defense restores throughput.
