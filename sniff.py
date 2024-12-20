#!/usr/bin/env python

from scapy.all import *
from scapy.fields import *


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
    
def get_interfaces():
    return [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']

ROUTE_PROTO_ID = 143

bind_layers(IP, RoutePacket, proto=ROUTE_PROTO_ID)


def process_route_packet(pkt):
    if RoutePacket in pkt:
        print("Pacote de rota recebido!")
        for route in pkt[RoutePacket].routes:
            print(f"Rota: {route.network}/{route.mask} via {route.next_hop} com custo {route.cost}")


def example(pkt):
    if IP in pkt:
        pkt[IP].show()  # IP NORMAL
    
    if RoutePacket in pkt:  # NOSSO PROTOCOLO
        process_route_packet(pkt)  # Processa a tabela... TO DO


interfaces = get_interfaces()
sniff(iface=interfaces, filter=f"ip proto {ROUTE_PROTO_ID} or ip", prn=example)
