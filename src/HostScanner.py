import argparse
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import threading
import time
import nmap

parser = argparse.ArgumentParser(description="T2 Lab Redes")
parser.add_argument("ip", nargs="?", default="10.32.143.0/24", help="Endereco IP e Mascara. ex: 10.32.143.0/24")
parser.add_argument("timeout", nargs="?", default="10", help="Tempo limite de execucao em milisegundos")
args = parser.parse_args()

totl_init_time = 0
total_end_time = 0
total_runtime = 0

def start_time():
    global totl_init_time
    totl_init_time = time.time()

def stop_time():
    global total_end_time, total_runtime
    total_end_time = time.time()
    total_runtime = total_end_time - totl_init_time

def formatar_tempo(segundos):
    minutos = int(segundos // 60)
    segundos_restantes = int(segundos % 60)
    return f"{minutos}:{segundos_restantes:02}"

def lista_enderecos(ip_range):
    rede = ipaddress.ip_network(ip_range, strict=False)
    hosts = [str(host) for host in rede.hosts()]
    return hosts

def scan_host(endereco_host, timeout):
    local_init = 0
    local_end = 0
    response_time = 0
    
    scanner = nmap.PortScanner()

    local_init= time.time()
    scanner.scan(hosts=endereco_host, arguments=f'-sn --host-timeout {timeout}ms')
    local_end = time.time()

    response_time = (local_end - local_init) * 1000

    if endereco_host in scanner.all_hosts():
        print(f"Host : {endereco_host} ({scanner[endereco_host].hostname()}), response time: {response_time} ms")

def scan_all_hosts(ip_range, timeout):
    threads = []
    hosts = lista_enderecos(ip_range=ip_range)

    for host in hosts:
        thread = threading.Thread(target=scan_host, args=(host, timeout))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def scan_all_hosts_thread_pool(ip_range, timeout):
    hosts = lista_enderecos(ip_range=ip_range)
    with ThreadPoolExecutor(max_workers=20) as executor:  # Limita a 10 threads paralelas
        executor.map(lambda host: scan_host(host, timeout), hosts)

start_time()

ip_range = args.ip
timeout = args.timeout
print(ip_range)
print(f"{timeout}ms")

# scan_all_hosts(ip_range=ip_range, timeout=timeout)
scan_all_hosts_thread_pool(ip_range=ip_range,timeout=timeout)

stop_time()
print(f"total_runtime: {formatar_tempo(total_runtime)}s")