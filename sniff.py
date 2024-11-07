#!/usr/bin/env python

from scapy.all import *
from scapy.fields import *

# --- Definições do Pacote do Protocolo de Rotas ---

class RouteEntry(Packet):
    fields_desc = [
        IPField("network", "0.0.0.0"),
        IPField("mask", "255.255.255.0"),
        IPField("next_hop", "0.0.0.0")
    ]

class RoutePacket(Packet):
    fields_desc = [
        ByteField("protocol_id", 99),  # Identificador para nosso protocolo personalizado
        ByteField("num_routes", 0),    # Número de entradas de rota
        PacketListField("routes", [], RouteEntry)
    ]

# Bind do novo protocolo ao Ethernet
bind_layers(Ether, RoutePacket, type=0x1234)

# --- Função para Processar Pacotes ---

def process_route_packet(pkt):
    if RoutePacket in pkt:
        print("Pacote de rota recebido!")
        for route in pkt[RoutePacket].routes:
            print(f"Rota: {route.network}/{route.mask} via {route.next_hop}")
            # Aqui você pode adicionar lógica para atualizar a tabela de rotas

# --- Função de Captura ---

def example(pkt):
    if IP in pkt:
        pkt[IP].show()  # Mostra os detalhes do pacote IP normal
    
    if RoutePacket in pkt:  # Verifica se o pacote é do novo protocolo
        process_route_packet(pkt)  # Processa o pacote de rota

# Inicia a captura na interface especificada
sniff(iface='r-eth1', filter="ether proto 0x1234 or ip", prn=example)
