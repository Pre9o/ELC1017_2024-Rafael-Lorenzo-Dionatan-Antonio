from scapy.all import *
from scapy.fields import *
from threading import Thread
import time
import sys
import os
import re
import subprocess

time_for_send_packets = 10
alorithm_time = 30

'''
router_ip_to_name = {
    "10.1.1.254": "r1", "10.2.2.254": "r5", "10.3.3.254": "r1",
    "10.4.4.254": "r3", "10.5.5.254": "r2", "10.6.6.254": "r4",
    "10.7.7.254": "r3", "10.8.8.254": "r5", "10.9.9.254": "r1",
    "10.10.10.1": "r1", "10.10.10.2": "r5", "10.11.11.1": "r1",
    "10.11.11.2": "r2", "10.12.12.1": "r1", "10.12.12.2": "r3",
    "10.13.13.1": "r2", "10.13.13.2": "r4", "10.15.15.1": "r2",
    "10.15.15.2": "r3", "10.9.9.1": "h9", "10.1.1.1": "h1",
    "10.3.3.1": "h3", "10.4.4.1": "h4", "10.5.5.1": "h5",
    "10.6.6.1": "h6", "10.7.7.1": "h7", "10.2.2.1": "h2",
    "10.8.8.1": "h8"
}
'''

router_ip_to_name = {
    "10.1.1.254": "r2", "10.2.2.254": "r2", "10.3.3.254": "r3",
    "10.4.4.254": "r3", "10.5.5.254": "r4", "10.6.6.254": "r4",
    "10.7.7.254": "r5", "10.8.8.254": "r5", "10.9.9.254": "r5",
    "10.10.10.1": "r1", "10.10.10.2": "r2", "10.11.11.1": "r1",
    "10.11.11.2": "r3", "10.12.12.1": "r1", "10.12.12.2": "r4",
    "10.13.13.1": "r1", "10.13.13.2": "r5", "10.1.1.1": "h1",
    "10.2.2.1": "h2", "10.3.3.1": "h3", "10.4.4.1": "h4",
    "10.5.5.1": "h5", "10.6.6.1": "h6", "10.7.7.1": "h7",
    "10.8.8.1": "h8", "10.9.9.1": "h9"
}

def dijkstra(graph, start):
    visited = {start: (0, None)}  # Armazena o custo e a aresta
    path = {}

    nodes = set(graph.nodes.keys())

    while nodes:
        min_node = None
        for node in nodes:
            if node in visited:
                if min_node is None:
                    min_node = node
                elif visited[node][0] < visited[min_node][0]:  # Compara os custos
                    min_node = node

        if min_node is None:
            break

        nodes.remove(min_node)
        current_weight = visited[min_node][0]

        for edge in graph.nodes[min_node].edges:
            weight = current_weight + edge.cost
            if edge.node2 not in visited or weight < visited[edge.node2][0]:
                visited[edge.node2] = (weight, edge)  # Armazena o custo e a aresta
                if min_node == start:
                    path[edge.node2] = (min_node, edge.network, edge.mask, edge.next_hop, edge.cost)
                else:
                    path[edge.node2] = (min_node, edge.network, edge.mask, path[min_node][3], edge.cost)

    # Construir os caminhos completos
    full_paths = {}
    for node in visited:
        full_path = []
        current = node
        while current is not None:
            full_path.insert(0, current)
            current = path.get(current, (None,))[0]
        full_paths[node] = full_path

    return visited, full_paths, path

def new_router_table(graph, router_name):
    visited, full_paths, path = dijkstra(graph, router_name)
    router_table = []
    for node, (cost, edge) in visited.items():
        if node == router_name:
            continue
        
        path_info = path[node]
        next_hop = path_info[3]  # next_hop do primeiro movimento
        network = path_info[1]  # network do destino
        mask = path_info[2]  # mask do destino
        cost = path_info[4]  # cost do destino

        print(f"Calculando rota para {node} via {next_hop} com custo {cost}")
        
        router_table.append((network, mask, next_hop, cost))
        
        # Executa o comando para adicionar ou substituir a rota
        print(f"Adicionando rota para {network}/{mask} via {next_hop} com custo {cost}")
        
        subprocess.run(['ip', 'route', 'replace', f"{network}{mask}", 'via', next_hop, 'metric', str(cost)], text=True)
    return router_table

class Edge:
    def __init__(self, node1, node2, network, mask, next_hop, cost) -> None:
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
            print(route)
            network = route[0]
            mask = route[1]
            next_hop = route[2]
            cost = route[3]
            node1 = self.get_or_create_node(router_name)
            node2 = self.get_or_create_node(router_ip_to_name[next_hop])

            self.add_edge(node1, node2, network, mask, next_hop, cost)
            
    def get_number_of_nodes(self):
        return len(self.nodes)

    def get_or_create_node(self, node_name):
        if node_name not in self.nodes:
            node = Node(node_name)
            self.nodes[node_name] = node
        return self.nodes[node_name]
    
    def get_all_routes(self):
        routes = set()
        for node_name, node in self.nodes.items():
            if node_name in ['r1', 'r2', 'r3', 'r4', 'r5']:
                for edge in node.edges:
                    route = tuple(sorted([edge.node1, edge.node2]))
                    routes.add((edge.network, edge.mask, edge.next_hop, edge.cost, edge.node1))
        return routes
    
    def add_edge(self, node1, node2, network, mask, next_hop, cost):
        if node1.name not in ['r1', 'r2', 'r3', 'r4', 'r5']:
            return

        print(f"Adicionando aresta entre {node1.name} e {node2.name}")
        for edge in node1.edges:
            if (edge.node1 == node1.name and edge.node2 == node2.name) or (edge.node1 == node2.name and edge.node2 == node1.name):
                return       
        
        edge1 = Edge(node1.name, node2.name, network, mask, next_hop, cost)
        self.nodes[node1.name].add_edge(edge1)

    def get_node(self, node_name):
        return self.nodes.get(node_name)

class RouteEntry(Packet):
    def extract_padding(self, s):
        return '', s
    
    fields_desc = [
        IPField("network", "0.0.0.0"),
        StrFixedLenField("mask", "/24", length=3),
        IPField("next_hop", "0.0.0.0"),
        IntField("cost", 0),
        StrFixedLenField("router_name", "r1", length=2)

    ]

class RoutePacket(Packet):
    def extract_padding(self, s):
        return '', s
    
    fields_desc = [
        ByteField("protocol_id", 143),  
        ByteField("num_routes", 0),    
        PacketListField("routes", [], RouteEntry, count_from=lambda pkt: pkt.num_routes)
    ]

ROUTE_PROTO_ID = 143 

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
            mask = f"/{match.group(2)}" 
            next_hop = match.group(3)
            cost = int(match.group(4))

            routes.append((network, mask, next_hop, cost))
    return routes

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

def send_route_table(neighbors, NetworkGraphforRouter, router_name):
    routes = NetworkGraphforRouter.get_all_routes()
    route_packet = RoutePacket(num_routes=len(routes))
    route_packet.routes = [RouteEntry(network=route[0], mask=route[1], next_hop=route[2], cost=route[3], router_name=route[4]) for route in routes]
    for interface, neighbor in neighbors.items():
        print(routes)
        send(IP(dst=neighbor, proto=ROUTE_PROTO_ID)/route_packet, iface=interface)
        print(f"Route table sent to {neighbor} on interface {interface}")

def process_route_packet(pkt, NetworkGraphforRouter):
    if IP in pkt:
        pkt[IP].show()  # IP NORMAL
        
    if RoutePacket in pkt:
        print("Pacote de rota recebido!")
        for route in pkt[RoutePacket].routes:
            print(f"Rota: {route.network}{route.mask.decode('utf-8')} via {route.next_hop} com custo {route.cost}")
            
        for route in pkt[RoutePacket].routes:
            node1 = NetworkGraphforRouter.get_or_create_node(route.router_name.decode('utf-8'))
            node2 = NetworkGraphforRouter.get_or_create_node(router_ip_to_name[route.next_hop])
            NetworkGraphforRouter.add_edge(node1, node2, route.network, route.mask.decode('utf-8'), route.next_hop, route.cost)
            
        print("Tabela de rota atualizada!")
        for node_name, node in NetworkGraphforRouter.nodes.items():
            print(f"Node: {node_name}")
            for edge in node.edges:
                print(f"  {edge.network}{edge.mask} via {edge.next_hop} com custo {edge.cost}")

def get_interfaces():
    return [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']

def periodic_route_sender(NetworkGraphforRouter, router_name, interval=1):
    while True:
        initial_time = time.time()
        while time.time() - initial_time < time_for_send_packets:
            neighbors = get_neighbors()
            send_route_table(neighbors, NetworkGraphforRouter, router_name)
            time.sleep(interval)
        
        new_router_table(NetworkGraphforRouter, router_name)
        
        time.sleep(alorithm_time)

def main(router_name):
    NetworkGraphforRouter = NetworkGraph()
    routes = get_router_table()

    NetworkGraphforRouter.add_initial_routes(routes, router_name)
    
    sender_thread = Thread(target=periodic_route_sender, args=(NetworkGraphforRouter, router_name))
    sender_thread.daemon = True
    sender_thread.start()

    interfaces = get_interfaces()
    sniff(iface=interfaces, filter=f"ip proto {ROUTE_PROTO_ID}", prn=lambda pkt: process_route_packet(pkt, NetworkGraphforRouter), store=0)

if __name__ == "__main__":
    if len(sys.argv) < 1:
        print("Usage: python route_exchange.py <router_name>")
        sys.exit(1)

    router_name = sys.argv[1]

    main(router_name)