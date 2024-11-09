#!/usr/bin/env python

from scapy.all import *
from scapy.fields import *


class RouteEntry(Packet):
    fields_desc = [
        IPField("network", "0.0.0.0"),
        IPField("mask", "255.255.255.0"),
        IPField("next_hop", "0.0.0.0")
    ]

class RoutePacket(Packet):
    fields_desc = [
        ByteField("protocol_id", 99),  # Identificador para nosso protocolo personalizado
        ByteField("num_routes", 0),    # Número de entradas de rota (PROVISÓRIO)
        PacketListField("routes", [], RouteEntry)
    ]

ROUTE_PROTO_ID = 143

bind_layers(IP, RoutePacket, proto=ROUTE_PROTO_ID)

HELLO_PROTO_ID = 200


class HelloPacket(Packet):
    name = "HelloPacket"
    fields_desc = [IPField("src", "0.0.0.0")]

bind_layers(IP, HelloPacket, proto=HELLO_PROTO_ID)

neighbors = set()


def process_route_packet(pkt):
    if HelloPacket in pkt:
        src_ip = pkt[HelloPacket].src
        neighbors.add(src_ip)
        print(f"Discovered neighbor: {src_ip}")
            
            

def example(pkt):
    if IP in pkt:
        pkt[IP].show()  # IP NORMAL
    
    if RoutePacket in pkt:  # NOSSO PROTOCOLO
        process_route_packet(pkt)  # Processa a tabela... TO DO

# Inicia a captura na interface especificada
sniff(iface='r5-eth1', filter=f"ip proto {HELLO_PROTO_ID}", prn=process_route_packet)
