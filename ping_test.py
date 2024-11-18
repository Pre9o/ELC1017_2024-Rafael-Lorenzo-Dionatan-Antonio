import subprocess

# Dicionário de IPs dos dispositivos na rede (hosts e roteadores) com seus nomes
devices = {
    "10.1.1.1": "h1", "10.2.2.1": "h2", "10.3.3.1": "h3", "10.4.4.1": "h4",
    "10.5.5.1": "h5", "10.6.6.1": "h6", "10.7.7.1": "h7", "10.8.8.1": "h8",
    "10.9.9.1": "h9", "10.1.1.254": "r1", "10.2.2.254": "r5", "10.3.3.254": "r1",
    "10.4.4.254": "r3", "10.5.5.254": "r2", "10.6.6.254": "r4", "10.7.7.254": "r3",
    "10.8.8.254": "r5", "10.9.9.254": "r1", "10.10.10.1": "r1", "10.10.10.2": "r5",
    "10.11.11.1": "r1", "10.11.11.2": "r2", "10.12.12.1": "r1", "10.12.12.2": "r3",
    "10.13.13.1": "r2", "10.13.13.2": "r4", "10.15.15.1": "r2", "10.15.15.2": "r3"
}

def ping(ip):
    try:
        output = subprocess.check_output(['ping', '-c', '1', ip], stderr=subprocess.STDOUT, universal_newlines=True)
        if "1 packets transmitted, 1 received" in output:
            return True
    except subprocess.CalledProcessError:
        return False

def main():
    for ip, name in devices.items():
        if ping(ip):
            print(f"{name} ({ip}) está funcionando")
        else:
            print(f"{name} ({ip}) não está respondendo")

if __name__ == "__main__":
    main()