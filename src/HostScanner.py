import scapy.all as scapy

# Função para fazer varredura ARP
def scan(ip_range):
    # Solicita um pacote ARP
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    # Envia o pacote e recebe as respostas
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    
    active_hosts = []
    for element in answered_list:
        active_hosts.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
        print(f"Host ativo encontrado - IP: {element[1].psrc}, MAC: {element[1].hwsrc}")
    
    return active_hosts
