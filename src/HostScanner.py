import argparse
import nmap

parser = argparse.ArgumentParser(description="T2 Lab Redes")
parser.add_argument("ip", help="Endereco IP e Mascara. ex: 10.32.143.0/24")
parser.add_argument("timeout", help="Tempo limite de execucao em milisegundos")
args = parser.parse_args()
ip_range = args.ip
timeout = args.timeout
print(ip_range)
print(f"{timeout}ms")

scanner = nmap.PortScanner()
scanner.scan(hosts=ip_range, arguments=f'-sn --host-timeout {timeout}ms')

for host in scanner.all_hosts():
    print(f"Host : {host} ({scanner[host].hostname()})")
    print(f"State : {scanner[host].state()}")