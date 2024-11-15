from scapy.all import *
from scapy.fields import *
from threading import Thread
import time
import sys
import os
import re
import subprocess

router_ip_to_name = {
    "10.1.1.254": "h1", "10.2.2.254": "h2", "10.3.3.254": "h3",
    "10.4.4.254": "h4", "10.5.5.254": "h5", "10.6.6.254": "h6",
    "10.7.7.254": "h7", "10.8.8.254": "h8", "10.9.9.254": "h9",
    "10.10.10.1": "r5", "10.10.10.2": "r1", "10.11.11.1": "r2",
    "10.11.11.2": "r1", "10.12.12.1": "r3", "10.12.12.2": "r1",
    "10.13.13.1": "r2", "10.13.13.2": "r4", "10.15.15.1": "r3",
    "10.15.15.2": "r2", "10.9.9.1": "r1", "10.1.1.1": "r1",
    "10.3.3.1": "r3", "10.4.4.1": "r4", "10.5.5.1": "r2",
    "10.6.6.1": "r4", "10.7.7.1": "r3", "10.2.2.1": "r5",
    "10.8.8.1": "r5"
}

class Edge:
    def __init__(self, node1, node2, node1_ip, node2_ip, network, mask, next_hop, cost) -> None:
        self.node1 = node1
        self.node2 = node2
        self.network = network
        self.mask = mask
        self.next_hop = next_hop
        self.cost = cost

class Node:
    def __init__(self, name) -> None:
        self.name = name
        self.edges = []

    def add_edge(self, edge):
        self.edges.append(edge)

class NetworkGraph:
    def __init__(self) -> None:
        self.nodes = {}

    def add_initial_routes(self, routes, router_name):
        for route in routes:
            network = route[0]
            mask = route[1]
            next_hop = route[2]
            cost = route[3]
            node1 = self.get_or_create_node(router_name)
            node2 = self.get_or_create_node(router_ip_to_name[next_hop])

            self.add_edge(node1, node2, network, mask, next_hop, cost)

    def get_or_create_node(self, node_name):
        if node_name not in self.nodes:
            node = Node(node_name)
            self.nodes[node_name] = node
        return self.nodes[node_name]
    
    def get_all_routes(self):
        routes = set()
        for node_name, node in self.nodes.items():
            for edge in node.edges:
                route = tuple(sorted((edge.network, edge.mask, edge.next_hop, edge.cost)))

    def add_edge(self, node1, node2, network, mask, next_hop, cost):
        edge1 = Edge(node1.name, node2.name, network, mask, next_hop, cost)
        edge2 = Edge(node2.name, node1.name, network, mask, next_hop, cost)
        self.nodes[node1.name].add_edge(edge1)
        self.nodes[node2.name].add_edge(edge2)

    def get_node(self, node_name):
        return self.nodes.get(node_name)

class RouteEntry(Packet):
    def extract_padding(self, s):
        return '', s
    
    fields_desc = [
        IPField("network", "0.0.0.0"),
        IPField("mask", "255.255.255.0"),
        IPField("next_hop", "0.0.0.0"),
        IntField("cost", 0),
        StrField("router_name", "")
    ]

class RoutePacket(Packet):
    def extract_padding(self, s):
        return '', s
    
    fields_desc = [
        ByteField("protocol_id", 143),  
        ByteField("num_routes", 0),    
        PacketListField("routes", [], RouteEntry, count_from=lambda pkt: pkt.num_routes)
    ]

ROUTE_PROTO_ID = 143  # ID DO NOSSO PROTOCOLO

# Bind do novo protocolo ao IP
bind_layers(IP, RoutePacket, proto=ROUTE_PROTO_ID)

def calculate_broadcast(ip, prefix):
    ip_bin = ''.join([bin(int(x)+256)[3:] for x in ip.split('.')])
    network = ip_bin[:prefix] + '0' * (32 - prefix)
    broadcast = network[:prefix] + '1' * (32 - prefix)
    broadcast_ip = '.'.join([str(int(broadcast[i:i+8], 2)) for i in range(0, 32, 8)])
    return broadcast_ip

def get_router_table():
    routes_output = subprocess.check_output(['ip', 'route'], text=True)
    routes = []
    for line in routes_output.split('\n'):
        match = re.search(r'(\d+\.\d+\.\d+\.\d+)/(\d+) via (\d+\.\d+\.\d+\.\d+) dev \S+ metric (\d+)', line)
        if match:
            network = match.group(1)
            mask = int(match.group(2))
            next_hop = match.group(3)
            cost = int(match.group(4))  # Captura o custo (métrica) da rota

            routes.append((network, mask, next_hop, cost))
    return routes

# Função para obter os IPs dos vizinhos
def get_neighbors():
    neighbors = {}
    interfaces = [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']
    print(f"Interfaces encontradas: {interfaces}")
    for interface in interfaces:
        ip_output = subprocess.check_output(['ip', 'addr', 'show', interface], text=True)
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', ip_output)
        if match:
            ip = match.group(1)
            if ip.endswith('.1') or ip.endswith('.2'):
                prefix = int(match.group(2))
                broadcast_ip = calculate_broadcast(ip, prefix)
                neighbors[interface] = broadcast_ip
                print(f"Interface: {interface}, IP: {ip}, Broadcast: {broadcast_ip}")
    return neighbors

# ENVIA A TABELA DE ROTAS PARA TODOS OS VIZINHOS
def send_route_table(neighbors, NetworkGraphforRouter):
    routes = NetworkGraphforRouter.get_all_routes()
    route_packet = RoutePacket(num_routes=len(routes))
    route_packet.routes = [RouteEntry(network=route[0], mask=route[1], next_hop=route[2], cost=route[3]) for route in routes]
    for interface, neighbor in neighbors.items():
        print(f"Sending route table to {neighbor} on interface {interface}")
        send(IP(dst=neighbor, proto=ROUTE_PROTO_ID)/route_packet, iface=interface)
        print(f"Route table sent to {neighbor} on interface {interface}")

def process_route_packet(pkt, my_ip):
    if RoutePacket in pkt:
        src_ip = pkt[IP].src
        if src_ip in my_ip.values():
            print(f"Ignorando pacote enviado pelo próprio roteador: {src_ip}")
            return
        print("Received route packet!")
        for route in pkt[RoutePacket].routes:
            print(f"Route: {route.network}/{route.mask} via {route.next_hop}")
        print(f"IP src: {src_ip}")
        print("=====================================")

def get_interfaces():
    return [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']

# ISSO NAO VAI FICAR AQUI, VAI SER DEFINIDO NO ALGORITMO DE ROTEAMENTO
def periodic_route_sender(NetworkGraphforRouter, interval=10):
    while True:
        neighbors = get_neighbors()
        send_route_table(neighbors, NetworkGraphforRouter)
        time.sleep(interval)

def main(router_name):
    NetworkGraphforRouter = NetworkGraph()
    routes = get_router_table()

    # Adiciona as rotas iniciais ao grafo
    NetworkGraphforRouter.add_initial_routes(routes, router_name)
    
    sender_thread = Thread(target=periodic_route_sender, args=(NetworkGraphforRouter,))
    sender_thread.daemon = True
    sender_thread.start()

    # Captura pacotes em todas as interfaces
    interfaces = get_interfaces()
    for interface in interfaces:
        sniff(iface=interface, filter=f"ip proto {ROUTE_PROTO_ID}", prn=process_route_packet, store=0)

if __name__ == "__main__":
    if len(sys.argv) < 1:
        print("Usage: python route_exchange.py <router_name>")
        sys.exit(1)

    router_name = sys.argv[1]

    main(router_name)