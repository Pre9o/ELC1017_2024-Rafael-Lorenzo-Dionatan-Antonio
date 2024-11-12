from scapy.all import *
from scapy.fields import *
from threading import Thread
import time
import sys
import os
import re

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

# Função para obter os IPs dos vizinhos
def get_neighbors():
    neighbors = {}
    output = os.popen('ip addr').read()
    interfaces = re.findall(r'\d+: (\w+):', output)
    for interface in interfaces:
        if interface != 'lo':
            ip_output = os.popen(f'ip addr show {str(interface)}').read()
            match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/\d+', ip_output)
            if match:
                ip = match.group(1)
                neighbors[interface] = ip
    return neighbors

# ENVIA A TABELA DE ROTAS PARA TODOS OS VIZINHOS
def send_route_table(routes, neighbors):
    print("Sending route table...")
    route_packet = RoutePacket(num_routes=len(routes))
    route_packet.routes = [RouteEntry(network=route[0], mask=route[1], next_hop=route[2]) for route in routes]
    for interface, neighbor in neighbors.items():
        print(f"Sending route table to {neighbor} on interface {interface}")
        send(IP(dst=neighbor, proto=ROUTE_PROTO_ID)/route_packet, iface=interface)
        print(f"Route table sent to {neighbor} on interface {interface}")

# ISSO NAO VAI FICAR AQUI, MAS SIM NO ROUTER
def process_route_packet(pkt):
    if RoutePacket in pkt:
        print("Received route packet!")
        for route in pkt[RoutePacket].routes:
            print(f"Route: {route.network}/{route.mask} via {route.next_hop}")
        print(f"IP src: {pkt[IP].src}")

def get_interfaces():
    return [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']

# ISSO NAO VAI FICAR AQUI, VAI SER DEFINIDO NO ALGORITMO DE ROTEAMENTO
def periodic_route_sender(routes, interval=10):
    while True:
        neighbors = get_neighbors()
        send_route_table(routes, neighbors)
        time.sleep(interval)

def main(routes):
    sender_thread = Thread(target=periodic_route_sender, args=(routes,))
    sender_thread.daemon = True
    sender_thread.start()

    # Captura pacotes em todas as interfaces
    interfaces = get_interfaces()
    for interface in interfaces:
        sniff(iface=interface, filter=f"ip proto {ROUTE_PROTO_ID}", prn=process_route_packet, store=0)

if __name__ == "__main__":
    # Example usage: python route_exchange.py "10.1.1.0/24:10.3.3.2,10.2.2.0/24:10.3.3.2"
    if len(sys.argv) < 2:
        print("Usage: python route_exchange.py <routes>")
        print("Example: python route_exchange.py '10.1.1.0/24:10.3.3.2,10.2.2.0/24:10.3.3.2'")
        sys.exit(1)
    
    raw_routes = sys.argv[1].split(',')
    
    routes = []
    for route in raw_routes:
        network, next_hop = route.split(':')
        network, mask = network.split('/')
        mask = '.'.join([str((0xffffffff << (32 - int(mask)) >> i) & 0xff) for i in [24, 16, 8, 0]])
        routes.append((network, mask, next_hop))

    main(routes)