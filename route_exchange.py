from scapy.all import *
from scapy.fields import *
from threading import Thread
import time
import sys

class RouteTable:
    def __init__(self) -> None:
        self.table = {"mask": [], "network": [], "next_hop": [], "interface": [], "cost": []}

    def add_route(self, mask, network, next_hop, interface, cost):
        self.table["mask"].append(mask)
        self.table["network"].append(network)
        self.table["next_hop"].append(next_hop)
        self.table["interface"].append(interface)
        self.table["cost"].append(cost)

    def get_route(self, network):
        for i in range(len(self.table["network"])):
            if self.table["network"][i] == network:
                return self.table["mask"][i], self.table["next_hop"][i], self.table["interface"][i], self.table["cost"][i]
        return None, None, None, None
    
    def update_route(self, mask, network, next_hop, interface, cost):
        for i in range(len(self.table["network"])):
            if self.table["network"][i] == network:
                self.table["mask"][i] = mask
                self.table["next_hop"][i] = next_hop
                self.table["interface"][i] = interface
                self.table["cost"][i] = cost
                return True
        return False

# --- Packet Definitions ---

class RouteEntry(Packet):
    fields_desc = [
        IPField("network", "0.0.0.0"),
        IPField("mask", "255.255.255.0"),
        IPField("next_hop", "0.0.0.0")
    ]

class RoutePacket(Packet):
    fields_desc = [
        ByteField("protocol_id", 99),  # Protocol identifier for our custom routing protocol
        ByteField("num_routes", 0),    # Number of route entries
        PacketListField("routes", [], RouteEntry)
    ]

# Bind layer so Scapy recognizes RoutePacket as a custom protocol
bind_layers(UDP, RoutePacket, dport=12345)

# --- Sending and Receiving Functions ---

# Sends the route table in RoutePacket format
def send_route_table(interface, routes):
    route_packet = RoutePacket(num_routes=len(routes))
    route_packet.routes = [RouteEntry(network=route[0], mask=route[1], next_hop=route[2]) for route in routes]
    send(IP(dst="255.255.255.255")/UDP(dport=12345)/route_packet, iface=interface)
    print(f"Route table sent on interface {interface}")

# Processes received route packets and updates the route table
def process_route_packet(pkt):
    if RoutePacket in pkt:
        print("Received route packet!")
        for route in pkt[RoutePacket].routes:
            print(f"Route: {route.network}/{route.mask} via {route.next_hop}")
        print(f"IP src: {pkt[IP].src}")

# Sets up periodic route table transmission
def periodic_route_sender(interface, routes, interval=10):
    while True:
        send_route_table(interface, routes)
        time.sleep(interval)

# --- Main Execution ---

def main(interface, routes):
    # Start thread for sending route tables periodically
    sender_thread = Thread(target=periodic_route_sender, args=(interface, routes))
    sender_thread.daemon = True
    sender_thread.start()

    # Start sniffing for route packets on the interface
    sniff(iface=interface, filter="udp port 12345", prn=process_route_packet)

if __name__ == "__main__":
    # Example usage: python route_exchange.py r1-eth2 "10.1.1.0/24:10.3.3.2,10.2.2.0/24:10.3.3.2"
    if len(sys.argv) < 3:
        print("Usage: python route_exchange.py <interface> <routes>")
        print("Example: python route_exchange.py r1-eth2 '10.1.1.0/24:10.3.3.2,10.2.2.0/24:10.3.3.2'")
        sys.exit(1)
    
    interface = sys.argv[1]
    raw_routes = sys.argv[2].split(',')
    
    routes = []
    for route in raw_routes:
        network, next_hop = route.split(':')
        network, mask = network.split('/')
        mask = '.'.join([str((0xffffffff << (32 - int(mask)) >> i) & 0xff) for i in [24, 16, 8, 0]])
        routes.append((network, mask, next_hop))

    main(interface, routes)