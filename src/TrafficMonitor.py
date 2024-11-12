from scapy.all import sniff, IP, TCP, UDP, DNS

class TrafficMonitor:
    def __init__(self, interface="Ethernet"):
        self.interface = interface

    def start_sniffer(self):
        print(f"Iniciando captura de pacotes na interface {self.interface}")
        sniff(iface=self.interface, prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            print(f"Pacote de IP: {ip_src} para {ip_dst}")
            
            if packet.haslayer(TCP) and packet[TCP].dport == 80:
                print("Pacote HTTP detectado")
                if packet.haslayer('Raw'):
                    print("Dados HTTP:", packet['Raw'].load.decode(errors='ignore'))
            
            elif packet.haslayer(UDP) and packet[UDP].dport == 53 and packet.haslayer(DNS):
                print("Pacote DNS detectado")
                if packet[DNS].qd:
                    print(f"Consulta DNS: {packet[DNS].qd.qname.decode('utf-8')}")
