from scapy.all import *
from scapy.fields import *
from threading import Thread
import time
import sys

class NetworkGraph:
    def __init__(self) -> None:
        self.graph = {}

    def add_edge(self, node1, node2, cost):
        if node1 not in self.graph:
            self.graph[node1] = {}
        self.graph[node1][node2] = cost

    def get_cost(self, node1, node2):
        if node1 in self.graph:
            if node2 in self.graph[node1]:
                return self.graph[node1][node2]
        return None

    def update_edge(self, node1, node2, cost):
        if node1 in self.graph:
            if node2 in self.graph[node1]:
                self.graph[node1][node2] = cost
                return True
        return False

# DEFINIÇÃO DO PACOTE (VAI MUDAR)

class RouteEntry(Packet):
    fields_desc = [
        IPField("network", "0.0.0.0"),
        IPField("mask", "255.255.255.0"),
        IPField("next_hop", "0.0.0.0")
    ]

class RoutePacket(Packet):
    fields_desc = [
        ByteField("protocol_id", 99),  
        ByteField("num_routes", 0),    
        PacketListField("routes", [], RouteEntry)
    ]

ROUTE_PROTO_ID = 143  # ID DO NOSSO PROTOCOLO

# Bind do novo protocolo ao IP
bind_layers(IP, RoutePacket, proto=ROUTE_PROTO_ID)


# ENVIA A TABELA DE ROTAS TO DO
def send_route_table(interface, routes):
    route_packet = RoutePacket(num_routes=len(routes))
    route_packet.routes = [RouteEntry(network=route[0], mask=route[1], next_hop=route[2]) for route in routes]
    send(IP(dst="10.1.1.1", proto=ROUTE_PROTO_ID)/route_packet, iface=interface)
    print(f"Route table sent on interface {interface}")

# ISSO NAO VAI FICAR AQUI, MAS SIM NO ROUTER
def process_route_packet(pkt):
    if RoutePacket in pkt:
        print("Received route packet!")
        for route in pkt[RoutePacket].routes:
            print(f"Route: {route.network}/{route.mask} via {route.next_hop}")
        print(f"IP src: {pkt[IP].src}")
    if HelloPacket in pkt:
        src_ip = pkt[HelloPacket].src
        neighbors.add(src_ip)
        print(f"Discovered neighbor: {src_ip}")
        

# ISSO NAO VAI FICAR AQUI, VAI SER DEFINIDO NO ALGORITMO DE ROTEAMENTO
def periodic_route_sender(interface, routes, interval=10):
    while True:
        send_route_table(interface, routes)
        time.sleep(interval)
        
HELLO_PROTO_ID = 200  # ID do protocolo de roteamento

class HelloPacket(Packet):
    name = "HelloPacket"
    fields_desc = [IPField("src", "0.0.0.0")]

bind_layers(IP, HelloPacket, proto=HELLO_PROTO_ID)

neighbors = set()

def send_hello_packet(interfaces):
    for interface in interfaces:
        pkt = IP(dst="255.255.255.255", proto=HELLO_PROTO_ID) / HelloPacket(src=get_if_addr(interface))
        send(pkt, iface=interface, verbose=False)

def periodic_hello_sender(interfaces, interval=10):
    while True:
        send_hello_packet(interfaces)
        time.sleep(interval)
        
def get_interfaces():
    return [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']

def main():
    #sender_thread = Thread(target=periodic_route_sender, args=(interface, routes))
    #sender_thread.daemon = True
    #sender_thread.start()
    interfaces = get_interfaces()
    
    hello_sender_thread = Thread(target=periodic_hello_sender, args=(interfaces,))
    hello_sender_thread.daemon = True
    hello_sender_thread.start()

    # NAO SERVE PRA NADA AQUI, VAI SER DEFINIDO NO ROUTER
    #sniff(iface=interface, filter=f"ip proto {ROUTE_PROTO_ID} or ip or ip proto {HELLO_PROTO_ID} ", prn=process_route_packet)


if __name__ == "__main__":
    # Example usage: python route_exchange.py r1-eth2 "10.1.1.0/24:10.3.3.2,10.2.2.0/24:10.3.3.2"
    '''if len(sys.argv) < 3:
        print("Usage: python route_exchange.py <interface> <routes>")
        print("Example: python route_exchange.py r1-eth2 '10.1.1.0/24:10.3.3.2,10.2.2.0/24:10.3.3.2'")
        sys.exit(1)'''
    
    # interface = sys.argv[1]
    #raw_routes = sys.argv[2].split(',')
    
    '''routes = []
    for route in raw_routes:
        network, next_hop = route.split(':')
        network, mask = network.split('/')
        mask = '.'.join([str((0xffffffff << (32 - int(mask)) >> i) & 0xff) for i in [24, 16, 8, 0]])
        routes.append((network, mask, next_hop))
'''
    main()