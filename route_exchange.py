from scapy.all import *
from scapy.fields import *
from threading import Thread
import time
import sys
import os
import re
import subprocess

class Edge:
    def __init__(self, node1_ip, mask, node2_ip, cost) -> None:
        self.node1_ip = node1_ip
        self.mask = mask
        self.node2_ip = node2_ip
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

    def add_initial_routes(self, routes):
        for route in routes:
            node1_name = route[0]
            mask = route[1]
            node2_name = route[2]
            cost = route[3]
            node1 = self.get_or_create_node(node1_name)
            node2 = self.get_or_create_node(node2_name)
            self.add_edge(node1, mask, node2, cost)

    def get_or_create_node(self, node_name):
        if node_name not in self.nodes:
            node = Node(node_name)
            self.nodes[node_name] = node
        return self.nodes[node_name]
    
    def get_all_routes(self):
        routes = set()
        for node_name, node in self.nodes.items():
            for edge in node.edges:
                route = tuple(sorted((edge.node1_ip, edge.node2_ip))) + (edge.mask, edge.cost)
                routes.add(route)
        return list(routes)

    def add_edge(self, node1, mask, node2, cost):
        edge1 = Edge(node1.name, mask, node2.name, cost)
        edge2 = Edge(node2.name, mask, node1.name, cost)
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
        IntField("cost", 0)
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
        print(match)
        if match:
            ip = match.group(1)
            if ip.endswith('.1'):
                prefix = int(match.group(2))
                broadcast_ip = calculate_broadcast(ip, prefix)
                neighbors[interface] = broadcast_ip
                print(f"Interface: {interface}, IP: {ip}, Broadcast: {broadcast_ip}")
    return neighbors

# ENVIA A TABELA DE ROTAS PARA TODOS OS VIZINHOS
def send_route_table(neighbors, NetworkGraphforRouter):
    print("Sending route table...")
    routes = NetworkGraphforRouter.get_all_routes()
    route_packet = RoutePacket(num_routes=len(routes))
    route_packet.routes = [RouteEntry(network=route[0], mask=route[1], next_hop=route[2], cost=route[3]) for route in routes]
    for interface, neighbor in neighbors.items():
        print(f"Sending route table to {neighbor} on interface {interface}")
        send(IP(dst=neighbor, proto=ROUTE_PROTO_ID)/route_packet, iface=interface)
        print(f"Route table sent to {neighbor} on interface {interface}")

def process_route_packet(pkt):
    if RoutePacket in pkt:
        print("Received route packet!")
        for route in pkt[RoutePacket].routes:
            print(f"Route: {route.network}/{route.mask} via {route.next_hop}")
        print(f"IP src: {pkt[IP].src}")
        pkt.show()
        print("=====================================")

def get_interfaces():
    return [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']

# ISSO NAO VAI FICAR AQUI, VAI SER DEFINIDO NO ALGORITMO DE ROTEAMENTO
def periodic_route_sender(NetworkGraphforRouter, interval=10):
    while True:
        neighbors = get_neighbors()
        send_route_table(neighbors, NetworkGraphforRouter)
        time.sleep(interval)

def main():
    NetworkGraphforRouter = NetworkGraph()
    routes = get_router_table()

    # Adiciona as rotas iniciais ao grafo
    NetworkGraphforRouter.add_initial_routes(routes)
    
    sender_thread = Thread(target=periodic_route_sender, args=(NetworkGraphforRouter,))
    sender_thread.daemon = True
    sender_thread.start()

    # Captura pacotes em todas as interfaces
    interfaces = get_interfaces()
    for interface in interfaces:
        sniff(iface=interface, filter=f"ip proto {ROUTE_PROTO_ID}", prn=process_route_packet, store=0)

if __name__ == "__main__":
    main()