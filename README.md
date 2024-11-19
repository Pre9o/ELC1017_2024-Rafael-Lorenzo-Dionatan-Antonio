# Link State Algorithm using Mininet

![Mininet](https://mininet.org/images/mininet-logo.png)

## Descrição dos Arquivos

- **1-topo-fwd.py**: Executa a topografia em malha.
- **2-topo-fwd.py**: Executa a topografia em estrela.
- **ping_test.py**: Implementação do pingall do ponto de vista de um host.
- **route_exchange.py**: Executa o algoritmo de roteamento - Link State - em cada roteador individualmente.
- **sniff.py**: Sniff das interfaces de rede.

## Instruções para Execução do Algoritmo

1. **Abra o terminal de cada roteador utilizando o "xterm"**:
    ```sh
    xterm r1 r2 r3 r4 r5
    ```

2. **Execute o algoritmo de roteamento em cada roteador**:
    ```sh
    python3 route_exchange.py [nome do roteador]
    ```
    Exemplo:
    ```sh
    python3 route_exchange.py r1
    ```

3. **Aperte "enter" em cada terminal de forma contínua**:
    - Depois que todos os roteadores estiverem com a chamada para o código escrita, aperte "enter" em cada terminal de forma contínua para iniciar o algoritmo.

## Autor

Rafael Carneiro Pregardier