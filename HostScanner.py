import socket
import struct
import time

class HostScanner:
    def __init__(self, network):
        self.network = network

    def checksum(self, data):
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i + 1] if (i + 1) < len(data) else 0)
            s = s + w
        s = (s >> 16) + (s & 0xFFFF)
        s = s + (s >> 16)
        return ~s & 0xFFFF

    def icmp_request(self, dest_addr, timeout=1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        
        packet_id = int((time.time() * 1000) % 65535)
        packet = struct.pack("bbHHh", 8, 0, 0, packet_id, 1)
        packet = struct.pack("bbHHh", 8, 0, self.checksum(packet), packet_id, 1)

        try:
            sock.sendto(packet, (dest_addr, 1))
            start_time = time.time()
            sock.recv(1024)
            return time.time() - start_time
        except socket.timeout:
            return None

    def scan_network(self):
        # Aqui você deve iterar sobre os IPs da rede e chamar icmp_request para cada um
        pass

#descobrir hosts ativos na rede. enviando pacotes ICMP para identificar dispositivos conectados