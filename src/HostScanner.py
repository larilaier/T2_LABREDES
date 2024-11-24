import argparse
import ipaddress
from socket import socket, SOCK_RAW, AF_INET
import struct
import threading
import time


parser = argparse.ArgumentParser(description="T2 Lab Redes")
parser.add_argument("ip", nargs="?", default="10.32.143.0/24", help="Endereco IP e Mascara. ex: 10.32.143.0/24")
parser.add_argument("timeout", nargs="?", default="500", help="Tempo limite de execucao em milisegundos")
args = parser.parse_args()

totl_init_time = 0
total_end_time = 0
total_runtime = 0

def start_time() -> None:
    """
    Inicia a contagem de tempo para medir a duracao da execucao do programa.
    
    Essa funcao registra o tempo atual em uma variavel global (totl_init_time),
    permitindo calcular a duracao total da execucao posteriormente.

    Args:
        None
    
    Returns:
        None
    """
    global totl_init_time
    totl_init_time = time.time()

def stop_time() -> None:
    """
    Finaliza a contagem de tempo e calcula a duracao total da execucao.

    Essa funcao registra o tempo atual em uma variavel global (total_end_time),
    calcula o tempo total de execucao e armazena o resultado em outra variavel global (total_runtime).

    Args:
        None

    Returns:
        None
    """
    global total_end_time, total_runtime
    total_end_time = time.time()
    total_runtime = total_end_time - totl_init_time

def formatar_tempo(segundos:float) -> str:
    """
    Converte um valor de tempo em segundos para o formato "minutos:segundos".

    Args:
        segundos (float): Tempo em segundos.

    Returns:
        str: Tempo formatado no estilo "MM:SS".
    """
    minutos = int(segundos // 60)
    segundos_restantes = int(segundos % 60)
    return f"{minutos}:{segundos_restantes:02}"

def imprime_enderecos(active_hosts:list) -> None:
    """
    Exibe os enderecos IPv4 e tempos de resposta dos hosts ativos.

    Args:
        active_hosts (list): Lista de tuplas contendo o IP do host (str) e o tempo de resposta (float).

    Returns:
        None
    """
    for host in active_hosts:
        print(f"IPv4: {host[0]}, Response time: {host[1]:.2f} ms")

def lista_enderecos(ip_range:str) -> list:
    """
    Gera uma lista de enderecos IP no intervalo especificado.

    Args:
        ip_range (str): Intervalo de IPs no formato CIDR (ex.: "192.168.1.0/24").

    Returns:
        list: Lista de enderecos IP (str) no intervalo fornecido.
    """
    rede = ipaddress.ip_network(ip_range, strict=False)
    hosts = [str(host) for host in rede.hosts()]
    return hosts

def cria_cabecalho_ethernet(mac_dest:str, mac_orig:str, protocol:int) -> bytes:
    """
    Cria um cabecalho Ethernet com os enderecos MAC e o protocolo especificado.

    Args:
        mac_dest (str): Endereco MAC de destino no formato "AA:BB:CC:DD:EE:FF".
        mac_orig (str): Endereco MAC de origem no formato "AA:BB:CC:DD:EE:FF".
        protocol (int): Tipo Ethernet (ex.: 0x0800 para IPv4).

    Returns:
        bytes: Cabecalho Ethernet formatado.
    """    
    mac_dest_bytes = bytes.fromhex(mac_dest.replace(':', ''))
    mac_orig_bytes = bytes.fromhex(mac_orig.replace(':', ''))

    ethernet_header = struct.pack(
        "!6s6sH",
        mac_dest_bytes,
        mac_orig_bytes,
        protocol
    )
    return ethernet_header

def cria_pacote_icmp(identificador:int , sequencia:int) -> bytes:
    """
    Cria o cabeçalho ICMP Echo Request.
    
    Args:
        identificador (int): Identificador único do pacote.
        sequencia (int): Número de sequência.
    
    Returns:
        bytes: Pacote ICMP formatado.
    """
    tipo = 8
    codigo = 0
    checksum = 0
    
    header = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, sequencia)

    checksum = calcula_checksum(header)

    header = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, sequencia)

    return header

def calcula_checksum(data: bytes) -> int:
    """
    Calcula o checksum de um pacote ICMP.

    O checksum é calculado somando todas as palavras de 16 bits (2 bytes consecutivos)
    do pacote. Se o número total de bytes for ímpar, o último byte é tratado como
    se estivesse acompanhado de um byte 0. Após a soma, o resultado é ajustado para
    caber em 16 bits e complementado bit a bit.

    Args:
        data (bytes): Dados do pacote ICMP.

    Returns:
        int: Checksum calculado.
    """
    soma = 0
    n = len(data)

    for i in range(0, n, 2): # Processa dois bytes por vez

        # Obtem o primeiro byte como menos significativo (Least Significant - LS)
        byte_ls = data[i + 1 ]

        # Confere se ha um segundo byte
        if i + 1 < n:
            byte_ms = data[i + 1] << 8 # Se existe, obtem como mais significativo (Most Significant - MS)
        else:
            byte_ms = 0

        # Desloca MSB para a esquerda 8 bits para formar palavra de 16 bits
        plvr_16bits = (byte_ms << 8) | byte_ls

        soma += plvr_16bits

        soma = (soma & 0xFFFF) + (soma >> 16)

    checksum = ~soma & 0xFFFF

    return checksum

def scan_host(endereco_host:str, timeout:int) -> None:
    """
    Realiza um ping em um host especifico enviando um pacote RAW.

    Args:
        endereco_host (str): Endereco IP do host a ser analisado.
        timeout (int): Tempo limite para resposta em milissegundos.

    Returns:
        None: Placeholder para implementacao futura.
    """
    raw_socket = socket(AF_INET, SOCK_RAW)
    raw_socket.bind(("eth1", 0))
    src_addr = "\x01\x02\x03\x04\x05\x06"
    dst_addr = "\x01\x02\x03\x04\x05\x06"
    payload = ("["*30)+"PAYLOAD"+("]"*30)
    ethertype = "\x08\x01"
    raw_socket.send(dst_addr+src_addr+ethertype+payload)

def thread_scan(host:str, timeout:int, active_hosts:list, lock:threading.Lock) -> None:
    """
    Realiza o escaneamento de um host em uma thread separada e armazena o resultado de forma segura.

    Args:
        host (str): Endereco IP do host a ser escaneado.
        timeout (int): Tempo limite para resposta em milissegundos.
        active_hosts (list): Lista compartilhada para armazenar os resultados dos hosts ativos.
        lock (threading.Lock): Lock para garantir acesso seguro a active_hosts.

    Returns:
        None
    """
    result = scan_host(endereco_host=host, timeout=timeout)
    if result:
        with lock:
            active_hosts.append(result)

def scan_all_hosts(ip_range:str, timeout:int) -> list:
    """
    Varre todos os enderecos IP em um intervalo especificado, verificando quais hosts estao ativos.

    Args:
        ip_range (str): Intervalo de IPs no formato CIDR (ex.: "192.168.1.0/24").
        timeout (int): Tempo limite para cada varredura em milissegundos.

    Returns:
        list: Lista de hosts ativos, cada um representado por uma tupla com IP e tempo de resposta.
    """
    threads = []
    active_hosts = []
    lock = threading.Lock()
    hosts = lista_enderecos(ip_range=ip_range)

    for host in hosts:
        thread = threading.Thread(target=thread_scan, args=(host, timeout, active_hosts, lock))
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