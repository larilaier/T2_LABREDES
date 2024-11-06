from scapy.all import ICMP, IP, sr1

class HostScanner:
    def __init__(self, network):
        self.network = network

    def scan_network(self):
        print(f"Iniciando varredura ICMP na rede: {self.network}")
        active_hosts = []

        # Envia uma mensagem ICMP para cada host da rede
        for ip in self._generate_ip_range(self.network):
            pkt = IP(dst=ip) / ICMP()
            response = sr1(pkt, timeout=1, verbose=0)
            if response:
                active_hosts.append({'ip': ip, 'status': 'active'})
                print(f"Host ativo encontrado - IP: {ip}")

        return active_hosts

    def _generate_ip_range(self, network):
        # Função para gerar o range de IPs da rede especificada
        ip_parts = network.split('.')
        base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
        return [f"{base_ip}.{i}" for i in range(1, 255)]  # IPs de 1 a 254
