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
        ByteField("protocol_id", 99),  # Identificador fixo 
        ByteField("num_routes", 0),    # Número de entradas de rota
        PacketListField("routes", [], RouteEntry)
    ]

bind_layers(Ether, RoutePacket, type=0x1234)


def send_route_table(interface, routes):
    # Criação do pacote
    route_packet = RoutePacket(num_routes=len(routes))
    route_packet.routes = [RouteEntry(network=route[0], mask=route[1], next_hop=route[2]) for route in routes]
    
    # Envio do pacote
    sendp(Ether()/route_packet, iface=interface)


def process_route_packet(pkt):
    if RoutePacket in pkt:
        print("Pacote de rota recebido!")
        for route in pkt[RoutePacket].routes:
            print(f"Rota: {route.network}/{route.mask} via {route.next_hop}")
            # Atualizar tabela de rotas aqui (conforme a lógica do roteador)

# Escuta pacotes na interface do roteador para processar os pacotes de rota
sniff(iface="r1-eth2", filter="ether proto 0x1234", prn=process_route_packet)
