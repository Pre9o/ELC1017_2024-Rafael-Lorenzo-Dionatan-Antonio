#!/usr/bin/env python

from scapy.all import *
from scapy.fields import *


class RouteEntry(Packet):
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

# Inicia a captura na interface especificada
sniff(iface='r5-eth1', filter=f"ip proto {ROUTE_PROTO_ID} or ip", prn=example)