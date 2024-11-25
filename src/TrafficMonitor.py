import socket
import struct
from datetime import datetime
import os
import argparse
from HostScanner import obtem_interface

class TrafficMonitor:
    def __init__(self, interface: str = None, output_file: str = "history.html"):
        """
        Inicializa o monitor de trafego.

        Args:
            interface (str): Interface de rede a ser monitorada. Se None, usa a funcao obtem_interface.
            output_file (str): Caminho do arquivo HTML onde o historico sera salvo.
        """
        self.interface = interface or obtem_interface()
        if not self.interface:
            raise RuntimeError("Nenhuma interface valida encontrada.")
        self.output_file = output_file
        self._initialize_html()

    def _initialize_html(self) -> None:
        """
        Inicializa o arquivo HTML para salvar o historico de navegacao.
        """
        with open(self.output_file, "w") as f:
            f.write("<html><head><title>Historico de Navegacao</title></head><body><ul>\n")
        print(f"[INFO] Arquivo {self.output_file} inicializado.")

    def save_entry(self, timestamp: str, ip: str, domain: str = None, url: str = None) -> None:
        """
        Salva uma entrada no arquivo HTML.

        Args:
            timestamp (str): Data e hora do acesso.
            ip (str): Endereco IP.
            domain (str, optional): Nome do dominio (DNS).
            url (str, optional): URL completa (HTTP).
        """
        with open(self.output_file, "a") as f:
            if domain:
                f.write(f"<li>{timestamp} - {ip} - {domain}</li>\n")
            elif url:
                f.write(f"<li>{timestamp} - {ip} - <a href='{url}'>{url}</a></li>\n")

    def parse_dns(self, dns_packet: bytes) -> str:
        """
        Extrai o dominio de um pacote DNS.

        Args:
            dns_packet (bytes): Dados do pacote DNS.

        Returns:
            str: Nome do dominio consultado.
        """
        domain = []
        i = 0
        length = dns_packet[i]

        while length != 0:
            domain.append(dns_packet[i + 1:i + 1 + length].decode())
            i += length + 1
            length = dns_packet[i]

        return ".".join(domain)

    def start_sniffing(self) -> None:
        """
        Inicia a captura de pacotes e analise de DNS e HTTP.
        """
        print(f"[INFO] Capturando pacotes na interface {self.interface}...")
        try:
            with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) as s:
                s.bind((self.interface, 0))
                while True:
                    packet, _ = s.recvfrom(65535)
                    self._process_packet(packet)
        except KeyboardInterrupt:
            print("\n[INFO] Monitor encerrado pelo usuario.")
            self._finalize_html()
        except Exception as e:
            print(f"[ERROR] Erro no monitoramento: {e}")

    def _process_packet(self, packet: bytes) -> None:
        """
        Processa um pacote capturado, filtrando DNS e HTTP.

        Args:
            packet (bytes): Dados do pacote capturado.
        """
        eth_header = packet[:14]
        eth = struct.unpack("!6s6sH", eth_header)
        eth_protocol = socket.ntohs(eth[2])

        # IPv4
        if eth_protocol == 0x0800:
            ip_header = packet[14:34]
            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dest_ip = socket.inet_ntoa(iph[9])

            # DNS (UDP)
            if protocol == 17:  # UDP
                udp_header = packet[34:42]
                udph = struct.unpack("!HHHH", udp_header)
                src_port = udph[0]
                dest_port = udph[1]

                if src_port == 53 or dest_port == 53:
                    dns_packet = packet[42:]
                    domain = self.parse_dns(dns_packet[12:])
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    self.save_entry(timestamp, src_ip, domain=domain)

            # HTTP (TCP)
            elif protocol == 6:  # TCP
                tcp_header = packet[34:54]
                tcph = struct.unpack("!HHLLBBHHH", tcp_header)
                src_port = tcph[0]
                dest_port = tcph[1]

                if src_port == 80 or dest_port == 80:  # HTTP
                    http_payload = packet[54:]
                    if b"GET" in http_payload or b"POST" in http_payload:
                        request = http_payload.decode(errors="ignore").split("\r\n")[0]
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        self.save_entry(timestamp, src_ip, url=request)

    def _finalize_html(self) -> None:
        """
        Finaliza o arquivo HTML ao encerrar o monitoramento.
        """
        with open(self.output_file, "a") as f:
            f.write("</ul></body></html>\n")
        print(f"[INFO] Historico salvo em {self.output_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TrafficMonitor - Monitora trafego DNS e HTTP.")
    parser.add_argument("-i", "--interface", help="Interface de rede a ser monitorada (padrao: detectada automaticamente).")
    parser.add_argument("-o", "--output", default="history.html", help="Arquivo HTML de saida (padrao: history.html).")
    args = parser.parse_args()

    monitor = TrafficMonitor(args.interface, args.output)
    monitor.start_sniffing()
