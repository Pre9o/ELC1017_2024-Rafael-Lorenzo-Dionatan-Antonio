#!/usr/bin/env python

from scapy.all import *

def example(pkt):
    pkt.show()  # Exibe o pacote capturado para verificação

    # Encaminha pacotes do h1 para h2 através das interfaces corretas
    if pkt.sniffed_on == 'r1-eth1' and pkt[IP].dst == '10.2.2.1':
        pkt[Ether].dst = None
        sendp(pkt, iface='r1-eth2')
    
    # Encaminha pacotes do h2 para h1 através das interfaces corretas
    elif pkt.sniffed_on == 'r1-eth2' and pkt[IP].dst == '10.1.1.1':
        pkt[Ether].dst = None
        sendp(pkt, iface='r1-eth1')
    
    else:
        return  # Ignora pacotes que não se destinam ao encaminhamento

# Inicia a captura de pacotes nas interfaces r1-eth1 e r1-eth2
sniff(iface=["r1-eth1", "r1-eth2"], filter='ip', prn=example)
