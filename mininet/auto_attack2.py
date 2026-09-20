#!/usr/bin/env python3
import re
import time

from mininet.net import Mininet
from mininet.log import setLogLevel

from topo import OffPathTopo  

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from colored_text import * 

SERVER_PORT = 5201
CLIENT_PORT = 40000

TEST_SECONDS = 30      # total iperf3 transfer duration
BASELINE_SECONDS = 8  
ATTACK_DURATION = TEST_SECONDS - BASELINE_SECONDS - 2  

IPERF_LOG = "/tmp/attack2_iperf.log"

# matches iperf3 interval lines
INTERVAL_RE = re.compile(
    r'\[\s*\d+\]\s+([\d.]+)-([\d.]+)\s+sec\s+[\d.]+\s+\S+\s+([\d.]+)\s+(\wbits/sec)'
)

def parse_throughput(log_text, baseline_seconds):
    base, attacked = [], []
    for m in INTERVAL_RE.finditer(log_text):
        start, end, rate, unit = float(m.group(1)), float(m.group(2)), float(m.group(3)), m.group(4)
        if not (0.9 < end - start < 1.1):
            continue  
        if unit == "Gbits/sec":
            rate *= 1000
        elif unit == "Kbits/sec":
            rate /= 1000
        if start < baseline_seconds:
            base.append(rate)
        else:
            attacked.append(rate)
    return base, attacked


def extract_mss_pmtu(ss_output):
    mss = re.search(r'mss:(\d+)', ss_output)
    pmtu = re.search(r'pmtu:(\d+)', ss_output)
    return (mss.group(1) if mss else '?'), (pmtu.group(1) if pmtu else '?')


def main():
    net = Mininet(topo=OffPathTopo(), controller=None)
    net.start()
    print(pink('☆ Network started'))

    for h in ('r', 'client'):
        net[h].cmd('for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done')

    print(cyan('☆ Reverse path filtering disabled on router and client'))
    client, server, attacker = net['client'], net['server'], net['attacker']

    print(yellow('\n⦿ Starting iperf3 server on %s' % server.IP()))
    server.cmd('iperf3 -s -p %d -D' % SERVER_PORT)
    time.sleep(1)

    print(yellow('\n⦿ Starting client -> server transfer for %ds (cport %d)'
          % (TEST_SECONDS, CLIENT_PORT)))
    client.cmd('iperf3 -c %s -p %d --cport %d -t %d > %s 2>&1 &'
               % (server.IP(), SERVER_PORT, CLIENT_PORT, TEST_SECONDS, IPERF_LOG))

    print(yellow('\n⦿ Waiting %ds for a clean baseline' % BASELINE_SECONDS))
    time.sleep(BASELINE_SECONDS)

    before = client.cmd('ss -tin')
    mss_before, pmtu_before = extract_mss_pmtu(before)
    print(cyan('      PMTU/MSS before attack: pmtu=%s mss=%s' % (pmtu_before, mss_before)))

    client.cmd('tcpdump -ni client-eth0 -c 1 -vv icmp > /tmp/icmp_check.txt 2>&1 &')
    time.sleep(2)

    print(yellow('\n⦿ Attacker sweeping forged ICMP Frag-Needed for %ds' % ATTACK_DURATION))
    attacker.cmd('python3 attack2_pmtu.py %d > /tmp/attack2.log 2>&1 &' % ATTACK_DURATION)

    # Check PMTU halfway through the attack
    time.sleep(ATTACK_DURATION / 2)
    mid = client.cmd('ss -tin')
    mss_mid, pmtu_mid = extract_mss_pmtu(mid)
    print(cyan('      PMTU/MSS MID-ATTACK: pmtu=%s mss=%s' % (pmtu_mid, mss_mid)))

    # Wait for attack to finish
    time.sleep(ATTACK_DURATION / 2 + 1)

    after = client.cmd('ss -tin')
    mss_after, pmtu_after = extract_mss_pmtu(after)
    print(cyan('      PMTU/MSS before attack: pmtu=%s mss=%s' % (pmtu_after, mss_after)))

    print(yellow('\n⦿Waiting for the transfer to finish'))
    time.sleep(max(0, TEST_SECONDS - BASELINE_SECONDS - ATTACK_DURATION) + 2)

    log_text = client.cmd('cat %s' % IPERF_LOG)
    base_samples, attacked_samples = parse_throughput(log_text, BASELINE_SECONDS)

    print(cyan('\n================ VERDICT ================'))
    print('  PMTU  before -> after : %s -> %s' % (pmtu_before, pmtu_after))
    print('  MSS   before -> after : %s -> %s' % (mss_before, mss_after))
    if base_samples and attacked_samples:
        base_avg = sum(base_samples) / len(base_samples)
        atk_avg = sum(attacked_samples) / len(attacked_samples)
        reduction = (base_avg - atk_avg) / base_avg * 100
        print('  Baseline avg (%d samples): %.1f Mbits/sec' % (len(base_samples), base_avg))
        print('  Attacked avg (%d samples): %.1f Mbits/sec' % (len(attacked_samples), atk_avg))
        print('  Throughput reduction: %.1f%%' % reduction)
        if pmtu_after != pmtu_before or reduction > 5:
            print(green('  RESULT: ATTACK SUCCEEDED -> PMTU/MSS shrank and/or throughput dropped.'))
        else:
            print(red('  RESULT: ATTACK FAILED -> no measurable change.'))
    else:
        print('  RESULT: INCONCLUSIVE -> not enough interval samples parsed from %s' % IPERF_LOG)
    print(cyan('  ===========================================\n'))

    client.cmd('pkill -f "iperf3 -c" 2>/dev/null')
    server.cmd('pkill -f "iperf3 -s" 2>/dev/null')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    main()
