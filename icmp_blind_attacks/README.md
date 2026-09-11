# Project 12 — ICMP Blind Attacks against TCP (RFC 5927)
CSE406 Cyber Security Sessional · Anisa (2105036) & Debashri (2105035)

Two off-path, "blind" attacks that spoof ICMP errors to hurt a TCP connection,
plus defenses. See the design report for the theory; this is the skeleton code.

## What's here
```
setup/              build 3 netns (client/server/attacker) + bridge   [Anisa]
common/             config.py + packet_utils.py — shared by all attacks [Anisa]
baseline/           start victim flow + capture "before" numbers        [Anisa]
attack1_reset/      Attack 1: blind connection RESET (custom kernel)     [Anisa]
attack2_throughput/ Attack 2a PMTU + 2b Source Quench (stock kernel)   [Debashri]
defense/            seq-check (A1) + min_pmtu floor / PLPMTUD (A2)   [both]
analysis/           parse logs -> CSV -> graphs for the report        [Debashri]
```
See **WORKLOAD.md** for who does what and in what order.

## Quick start
```bash
pip install -r requirements.txt
sudo apt install iperf3 tcpdump iproute2

sudo ./setup/setup_namespaces.sh          # 1. build the lab
./baseline/run_baseline.sh 60             # 2. see healthy throughput

# Attack 1 (needs custom-5.15 kernel to succeed):
cd attack1_reset && sudo ./run_attack1.sh

# Attack 2 (stock kernel):
cd attack2_throughput && sudo ./run_attack2.sh pmtu

# Defenses:
sudo ./defense/defense_pmtu_floor.sh      # then re-run Attack 2a
# (Attack 1 defense = re-run on the stock kernel; see defense/defense_seqcheck.md)

sudo ./setup/teardown_namespaces.sh       # cleanup
```

## Mapping to the Final-Report deliverables
- **(a) Steps / snapshots / victim screen** — `run_*.sh` are the steps;
  `baseline/capture.sh` pcaps + `ss` logs are the snapshots.
- **(b) Was it successful & why** — Attack 1 succeeds only on custom-5.15
  (relaxed seq check); Attack 2a succeeds on stock kernels (soft errors aren't
  seq-gated); Attack 2b likely a no-op (Linux ignores Source Quench since 2004).
- **(c) Output on attacker / victim / server** — attacker: send counts;
  client(victim): teardown or throughput drop in pcap + `ss`; server: flow ends
  or slows. Collected by `analysis/`.
- **(d) Countermeasures** — `defense/` (seq-in-window check, min_pmtu floor,
  PLPMTUD stretch) — this is where the 10% bonus comes from.
```
