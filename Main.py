import scapy.all as scapy
import socket

# Função para fazer varredura ARP
def scan(ip):
    # Solicita um pacote ARP
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combina a solicitação ARP com o pacote de broadcast
    arp_request_broadcast = broadcast/arp_request
    # Envia o pacote e recebe as respostas
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    active_hosts = []
    for element in answered_list:
        # Cria um dicionário com IP e MAC de hosts ativos
        active_hosts.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    
    return active_hosts

# Função para capturar pacotes
def capture_packets():
    # Captura pacotes e exibe o IP de origem e destino
    print("Iniciando captura de pacotes...")
    scapy.sniff(prn=process_packet, store=False, count=10)

# Função para processar pacotes
def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Pacote de IP: {ip_src} para {ip_dst}")

# Função principal
def main():
    ip_range = "10.1.64.0/24"
    print(f"Iniciando varredura de ARP na rede: {ip_range}")
    
    # Realiza a varredura ARP
    active_hosts = scan(ip_range)
    print("Hosts ativos:", active_hosts)
    
    # Inicia captura de pacotes
    capture_packets()

if __name__ == "__main__":
    main()
