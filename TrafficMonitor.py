import socket

class TrafficMonitor:
    def __init__(self, interface="eth0"):
        self.interface = interface

    def start_sniffer(self):
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((self.interface, 0))
        while True:
            raw_data, addr = sock.recvfrom(65536)
            self.process_packet(raw_data)

    def process_packet(self, data):
        # Aqui você pode implementar a detecção de pacotes HTTP e DNS
        if self.is_http_packet(data):
            print("Pacote HTTP detectado")
            # Extraia e salve os dados HTTP
        elif self.is_dns_packet(data):
            print("Pacote DNS detectado")
            # Extraia e salve os dados DNS

    def is_http_packet(self, data):
        return b"HTTP" in data

    def is_dns_packet(self, data):
        return data[23] == 17 and data[36:38] == b'\x00\x35'  # Porta 53 para DNS

#capturar e analisar o tráfego da rede