#!/usr/bin/env python3

import re
import time

from mininet.net import Mininet
from mininet.log import setLogLevel

from topo import OffPathTopo 

SERVER_PORT = 5201
CLIENT_PORT = 40000

TEST_SECONDS = 10   # how long the background iperf3 transfer runs for
SETTLE_TIME  = 3    # seconds to wait before attacking

from pathlib import Path
import sys
sys.path.append(str(Path(__file__).resolve().parent.parent))
from colored_text import * 

def is_established(ss_output, port):
    #Finds the ESTAB line in client port
    pattern = re.compile(r'ESTAB.*:%d\s' % port)
    return any(pattern.search(line) for line in ss_output.splitlines())


def main():
    net = Mininet(topo=OffPathTopo(), controller=None)
    net.start()

    print(pink('☆ Network started'))
    # Reverse path filtering turned off per interface of router and client 
    # in order to allowed spoofed packets to pass

    for h in ('r', 'client'):
        net[h].cmd('for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done')

    print(cyan('☆ Reverse path filtering disabled on router and client'))

    client, server, attacker = net['client'], net['server'], net['attacker']

    print(yellow('\n⦿ Starting iperf3 server on %s' % server.IP()))
    server.cmd('iperf3 -s -p %d -D' % SERVER_PORT)   
    time.sleep(1)

    print(yellow('⦿ Starting client -> server transfer on port %d (cport %d)'
          % (SERVER_PORT, CLIENT_PORT)))
    client.cmd('iperf3 -c %s -p %d --cport %d -t %d > /tmp/attack1_iperf.log 2>&1 &'
               % (server.IP(), SERVER_PORT, CLIENT_PORT, TEST_SECONDS))
    time.sleep(SETTLE_TIME)

    before = client.cmd('ss -t')
    alive_before = is_established(before, CLIENT_PORT)
    print(pink('☆ Connection ESTABLISHED before attack: %s' % alive_before))

    print(yellow('⦿ Sniffing ICMP on the client'))
    client.cmd('tcpdump -ni client-eth0 icmp -w /tmp/attack1_icmp.pcap > /dev/null 2>&1 &')
    time.sleep(1)

    print(yellow('⦿ Attacker sending the forged ICMP packet'))
    print(attacker.cmd('python3 attack1_reset.py'))

    time.sleep(2)
    client.cmd('pkill -f "tcpdump -ni client-eth0" 2>/dev/null')
    after = client.cmd('ss -t')
    alive_after = is_established(after, CLIENT_PORT)

    pkt_count = client.cmd(
        'tcpdump -nr /tmp/attack1_icmp.pcap 2>/dev/null | wc -l').strip()

    print(cyan('================ VERDICT ================'))
    print('       ICMP packets seen arriving at client : %s' % pkt_count)
    print('       connection ESTABLISHED before attack  : %s' % alive_before)
    print('       connection ESTABLISHED after attack   : %s' % alive_after)
    if alive_before and not alive_after:
        print(green('       RESULT: ATTACK SUCCEEDED -> connection was reset.'))
    elif alive_before and alive_after:
        print(red('       RESULT: ATTACK FAILED -> connection survived.'))
    else:
        print(yellow('       RESULT: INCONCLUSIVE -> connection was not up yet when'))
        print(yellow('               the attack fired. Increase SETTLE_TIME and retry.'))
    print(cyan('==========================================\n'))

    # cleanup background processes 
    client.cmd('pkill -f "iperf3 -c" 2>/dev/null')
    server.cmd('pkill -f "iperf3 -s" 2>/dev/null')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    main()
