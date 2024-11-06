from scapy.all import sniff

class TrafficMonitor:
    def __init__(self, interface="Ethernet"):
        self.interface = interface

    def start_sniffer(self):
        print(f"Iniciando captura de pacotes na interface {self.interface}")
        sniff(iface=self.interface, prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if packet.haslayer('IP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            print(f"Pacote de IP: {ip_src} para {ip_dst}")
            if packet.haslayer('TCP') and packet['TCP'].dport == 80:
                print("Pacote HTTP detectado")
            elif packet.haslayer('UDP') and packet['UDP'].dport == 53:
                print("Pacote DNS detectado")
