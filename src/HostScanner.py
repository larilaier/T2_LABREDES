import argparse
import ipaddress
import subprocess
import threading
import time

parser = argparse.ArgumentParser(description="T2 Lab Redes")
parser.add_argument("ip", nargs="?", default="10.32.143.0/24", help="Endereco IP e Mascara. ex: 10.32.143.0/24")
parser.add_argument("timeout", nargs="?", default="500", help="Tempo limite de execucao em milisegundos")
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

def imprime_enderecos(active_hosts):
    for host in active_hosts:
        print(f"IPv4: {host[0]}, Response time: {host[1]:.2f} ms")

def lista_enderecos(ip_range):
    rede = ipaddress.ip_network(ip_range, strict=False)
    hosts = [str(host) for host in rede.hosts()]
    return hosts

def scan_host(endereco_host, timeout):
    local_init = 0
    local_end = 0
    response_time = 0

    if subprocess.os.name == 'nt':
        command = ['ping', '-n', '1', '-w', str(timeout), endereco_host]
    else:
        command = ['ping', '-c', '1', '-W', str(int(timeout / 1000)), endereco_host]

    local_init= time.time()

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout/1000)
        
        local_end = time.time()
        response_time = (local_end - local_init) * 1000

        if result.returncode == 0:
            return [endereco_host, response_time]
        else:
            return None
    except subprocess.TimeoutExpired:
        return None

def scan_all_hosts(ip_range, timeout):
    threads = []
    active_hosts = []
    hosts = lista_enderecos(ip_range=ip_range)

    def thread_scan(host):
        result = scan_host(endereco_host=host, timeout=timeout)
        if result:
            active_hosts.append(result)

    for host in hosts:
        thread = threading.Thread(target=thread_scan, args=(host,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return active_hosts

start_time()

ip_range = args.ip
timeout = int(args.timeout)
print(ip_range)
print(f"{timeout}ms\n")

active_hosts = scan_all_hosts(ip_range=ip_range, timeout=timeout)

stop_time()

imprime_enderecos(active_hosts=active_hosts)

total_hosts = len(lista_enderecos(ip_range))
print(f"\nNúmero total de máquinas na rede: {total_hosts}")
print(f"Número de máquinas ativas: {len(active_hosts)}")
print(f"Tempo total de varredura: {formatar_tempo(total_runtime)}s\n")