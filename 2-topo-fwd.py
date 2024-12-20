from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class StarTopo(Topo):
    "Topologia em estrela com cinco roteadores e nove hosts"

    def build(self, **_opts):
        # Create routers
        r1 = self.addHost('r1', ip=None)  # Roteador central
        r2 = self.addHost('r2', ip=None)
        r3 = self.addHost('r3', ip=None)
        r4 = self.addHost('r4', ip=None)
        r5 = self.addHost('r5', ip=None)

        # Create hosts
        h1 = self.addHost('h1', ip='10.1.1.1/24', defaultRoute='via 10.1.1.254')
        h2 = self.addHost('h2', ip='10.2.2.1/24', defaultRoute='via 10.2.2.254')
        h3 = self.addHost('h3', ip='10.3.3.1/24', defaultRoute='via 10.3.3.254')
        h4 = self.addHost('h4', ip='10.4.4.1/24', defaultRoute='via 10.4.4.254')
        h5 = self.addHost('h5', ip='10.5.5.1/24', defaultRoute='via 10.5.5.254')
        h6 = self.addHost('h6', ip='10.6.6.1/24', defaultRoute='via 10.6.6.254')
        h7 = self.addHost('h7', ip='10.7.7.1/24', defaultRoute='via 10.7.7.254')
        h8 = self.addHost('h8', ip='10.8.8.1/24', defaultRoute='via 10.8.8.254')
        h9 = self.addHost('h9', ip='10.9.9.1/24', defaultRoute='via 10.9.9.254')

        # Add links with specific interfaces and IPs
        self.addLink(r1, r2, intfName1='r1-eth1', params1={'ip': '10.10.10.1/24'}, intfName2='r2-eth1', params2={'ip': '10.10.10.2/24'})
        self.addLink(r1, r3, intfName1='r1-eth2', params1={'ip': '10.11.11.1/24'}, intfName2='r3-eth1', params2={'ip': '10.11.11.2/24'})
        self.addLink(r1, r4, intfName1='r1-eth3', params1={'ip': '10.12.12.1/24'}, intfName2='r4-eth1', params2={'ip': '10.12.12.2/24'})
        self.addLink(r1, r5, intfName1='r1-eth4', params1={'ip': '10.13.13.1/24'}, intfName2='r5-eth1', params2={'ip': '10.13.13.2/24'})
        self.addLink(r2, h1, intfName1='r2-eth2', params1={'ip': '10.1.1.254/24'}, intfName2='h1-eth0', params2={'ip': '10.1.1.1/24'})
        self.addLink(r2, h2, intfName1='r2-eth3', params1={'ip': '10.2.2.254/24'}, intfName2='h2-eth0', params2={'ip': '10.2.2.1/24'})
        self.addLink(r3, h3, intfName1='r3-eth2', params1={'ip': '10.3.3.254/24'}, intfName2='h3-eth0', params2={'ip': '10.3.3.1/24'})
        self.addLink(r3, h4, intfName1='r3-eth3', params1={'ip': '10.4.4.254/24'}, intfName2='h4-eth0', params2={'ip': '10.4.4.1/24'})
        self.addLink(r4, h5, intfName1='r4-eth2', params1={'ip': '10.5.5.254/24'}, intfName2='h5-eth0', params2={'ip': '10.5.5.1/24'})
        self.addLink(r4, h6, intfName1='r4-eth3', params1={'ip': '10.6.6.254/24'}, intfName2='h6-eth0', params2={'ip': '10.6.6.1/24'})
        self.addLink(r5, h7, intfName1='r5-eth2', params1={'ip': '10.7.7.254/24'}, intfName2='h7-eth0', params2={'ip': '10.7.7.1/24'})
        self.addLink(r5, h8, intfName1='r5-eth3', params1={'ip': '10.8.8.254/24'}, intfName2='h8-eth0', params2={'ip': '10.8.8.1/24'})
        self.addLink(r5, h9, intfName1='r5-eth4', params1={'ip': '10.9.9.254/24'}, intfName2='h9-eth0', params2={'ip': '10.9.9.1/24'})

def run():
    "Topologia avançada com cinco roteadores e nove hosts"
    net = Mininet(topo=StarTopo(), controller=None)
    
    # Disable offload features for proper packet handling in Scapy
    for _, v in net.nameToNode.items():
        for itf in v.intfList():
            v.cmd('ethtool -K ' + itf.name + ' tx off rx off')
    
    net.start()

    # Habilitar o encaminhamento de IP em todos os roteadores
    for router in ['r1', 'r2', 'r3', 'r4', 'r5']:
        net[router].cmd('sysctl -w net.ipv4.ip_forward=1')
    
    # Adicionar rotas dos vizinhos em cada roteador
    net['r1'].cmd('ip route add 10.10.10.0/24 via 10.10.10.2 metric 2')  # r1 -> r2
    net['r1'].cmd('ip route add 10.11.11.0/24 via 10.11.11.2 metric 3')  # r1 -> r3
    net['r1'].cmd('ip route add 10.12.12.0/24 via 10.12.12.2 metric 2')  # r1 -> r4
    net['r1'].cmd('ip route add 10.13.13.0/24 via 10.13.13.2 metric 1')  # r1 -> r5

    net['r2'].cmd('ip route add 10.10.10.0/24 via 10.10.10.1 metric 3')  # r2 -> r1
    net['r2'].cmd('ip route add 10.1.1.0/24 via 10.1.1.1 metric 1')      # r2 -> h1
    net['r2'].cmd('ip route add 10.2.2.0/24 via 10.2.2.1 metric 1')      # r2 -> h2

    net['r3'].cmd('ip route add 10.11.11.0/24 via 10.11.11.1 metric 4')  # r3 -> r1
    net['r3'].cmd('ip route add 10.3.3.0/24 via 10.3.3.1 metric 1')      # r3 -> h3
    net['r3'].cmd('ip route add 10.4.4.0/24 via 10.4.4.1 metric 1')      # r3 -> h4

    net['r4'].cmd('ip route add 10.12.12.0/24 via 10.12.12.1 metric 2')  # r4 -> r1
    net['r4'].cmd('ip route add 10.5.5.0/24 via 10.5.5.1 metric 1')      # r4 -> h5
    net['r4'].cmd('ip route add 10.6.6.0/24 via 10.6.6.1 metric 1')      # r4 -> h6

    net['r5'].cmd('ip route add 10.13.13.0/24 via 10.13.13.1 metric 5')  # r5 -> r1
    net['r5'].cmd('ip route add 10.7.7.0/24 via 10.7.7.1 metric 1')      # r5 -> h7
    net['r5'].cmd('ip route add 10.8.8.0/24 via 10.8.8.1 metric 1')      # r5 -> h8
    net['r5'].cmd('ip route add 10.9.9.0/24 via 10.9.9.1 metric 1')      # r5 -> h9
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()