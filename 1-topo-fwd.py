from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class AdvancedTopo(Topo):
    "Two routers with two hosts"

    def build(self, **_opts):
        # Create routers
        r1 = self.addHost('r1', ip=None)
        r2 = self.addHost('r2', ip=None)

        # Create hosts
        h1 = self.addHost('h1', ip=None, defaultRoute='via 10.1.1.254')
        h2 = self.addHost('h2', ip=None, defaultRoute='via 10.2.2.254')
        
        # Host to Router 1
        self.addLink(h1, r1, intfName1='h1-eth0', params1={'ip': '10.1.1.1/24'},
                     intfName2='r1-eth1', params2={'ip': '10.1.1.254/24'})
        
        # Host to Router 2
        self.addLink(h2, r2, intfName1='h2-eth0', params1={'ip': '10.2.2.1/24'},
                     intfName2='r2-eth1', params2={'ip': '10.2.2.254/24'})
        
        # Router to Router link
        self.addLink(r1, r2, intfName1='r1-eth2', params1={'ip': '10.3.3.1/24'},
                     intfName2='r2-eth2', params2={'ip': '10.3.3.2/24'})

def run():
    "Advanced topology with two routers and route exchange testing"
    net = Mininet(topo=AdvancedTopo(), controller=None)
    
    # Disable offload features for proper packet handling in Scapy
    for _, v in net.nameToNode.items():
        for itf in v.intfList():
            v.cmd('ethtool -K ' + itf.name + ' tx off rx off')
    
    net.start()
    
    # Enable IP forwarding on routers
    r1, r2 = net.get('r1', 'r2')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')
    r2.cmd('sysctl -w net.ipv4.ip_forward=1')
    
    # Add static routes
    r1.cmd('ip route add 10.2.2.0/24 via 10.3.3.2')
    r2.cmd('ip route add 10.1.1.0/24 via 10.3.3.1')

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()
