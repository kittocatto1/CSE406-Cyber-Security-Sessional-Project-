"""
Mininet topology for the ICMP attack experiments.

Client, server, and attacker are placed on separate subnets connected through a Linux router (r).
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.cli import CLI
from mininet.log import setLogLevel

class LinuxRouter(Node):
    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1') #Forward packets between networks 
        # self.cmd('sysctl -w net.ipv4.conf.all.rp_filter=0') 

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0') 
        super().terminate()


class OffPathTopo(Topo):
    def build(self):

        r = self.addNode('r', cls=LinuxRouter, ip='10.0.1.254/24')

        client   = self.addHost('client',   ip='10.0.1.1/24', defaultRoute='via 10.0.1.254')
        server   = self.addHost('server',   ip='10.0.2.1/24', defaultRoute='via 10.0.2.254')
        attacker = self.addHost('attacker', ip='10.0.3.1/24', defaultRoute='via 10.0.3.254')

        self.addLink(client,   r, intfName2='r-eth1', params2={'ip': '10.0.1.254/24'})
        self.addLink(server,   r, intfName2='r-eth2', params2={'ip': '10.0.2.254/24'})
        self.addLink(attacker, r, intfName2='r-eth3', params2={'ip': '10.0.3.254/24'})
