import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import struct
import subprocess
import threading
import time
import uuid


parser = argparse.ArgumentParser(description="T2 Lab Redes")
parser.add_argument("ip", nargs="?", default="10.32.143.0/24", help="Endereco IP e Mascara. ex: 10.32.143.0/24")
parser.add_argument("timeout", nargs="?", default="500", help="Tempo limite de execucao em milisegundos")
args = parser.parse_args()

arp_cache_file = "arp_cache.json"

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

def load_arp_cache() -> dict:
    """
    Carrega o cache ARP de um arquivo local.

    Returns:
        dict: Cache ARP no formato {IP: MAC}.
    """
    if os.path.exists(arp_cache_file):
        with open(arp_cache_file, "r") as f:
            return json.load(f)
    return {}

def save_arp_cache(cache: dict) -> None:
    """
    Salva o cache ARP em um arquivo local.

    Args:
        cache (dict): Cache ARP no formato {IP: MAC}.
    """
    with open(arp_cache_file, "w") as f:
        json.dump(cache, f)

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

def obtem_endr_orig(ip_dest: str) -> tuple:
    """
    Obtém o endereço IP e MAC da própria máquina.

    Args:
        ip_dest (str): Endereço IP de destino (não usado para determinar o MAC local, mas necessário para lógica do socket).

    Returns:
        tuple: IP de origem (str), MAC de origem (str).

    Raises:
        ValueError: Se não for possível determinar os endereços.
    """
    try:
        # Obter IP de origem
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ip_dest, 1))
        ip_orig = s.getsockname()[0]
        s.close()

        # Obter MAC de origem
        mac_orig = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0, 8 * 6, 8)][::-1])
        return ip_orig, mac_orig
    except Exception as e:
        raise ValueError(f"Erro ao determinar IP/MAC de origem: {e}")

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
    try:    
        mac_dest_bytes = bytes.fromhex(mac_dest.replace(':', ''))
        mac_orig_bytes = bytes.fromhex(mac_orig.replace(':', ''))

        ethernet_header = struct.pack(
            "!6s6sH",
            mac_dest_bytes,
            mac_orig_bytes,
            protocol
        )
        return ethernet_header
    except Exception as e:
        # print(f"[DEBUG] ERRO NO CRIA CABECALHO ETHERNET: {e}")
        pass

def cria_cabecalho_ip(ip_orig: str, ip_dest: str, payload_length: int) -> bytes:
    """
    Cria o cabeçalho IP.

    Args:
        ip_orig (str): Endereço IP de origem (ex.: "192.168.1.100").
        ip_dest (str): Endereço IP de destino (ex.: "192.168.1.1").
        payload_length (int): Tamanho do payload (ex.: cabeçalho ICMP + dados).

    Returns:
        bytes: Cabeçalho IP formatado.
    """ 
    version_ihl = (4 << 4) | 5 # Versao IPv4 (4 bits) e IHL = 5 palavras (20 bytes)
    dscp_ecn = 0 # Tipo de servico
    total_length = 20 + payload_length # Tamanho total do pacote IP (cabecalho + payload)
    identification = 54321 # Identificacao do pacote
    flags_fragment_offset = 0 # Sem fragmentacao
    ttl = 64 # Time to live
    protocol = 1 # ICMP
    checksum = 0 # Inicialmente 0 para o calculo
    src_ip = socket.inet_aton(ip_orig) # Converte o IP de string para bytes
    dest_ip = socket.inet_aton(ip_dest) # Converte o IP de string para bytes

    # Monta o cabecalho com checksum 0 para calculo inicial
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,            # Versao e IHL
        dscp_ecn,               # DSCP e ECN
        total_length,           # Comprimento total
        identification,         # Identificacao
        flags_fragment_offset,  # Flags e offset de fragmentacao
        ttl,                    # TTL
        protocol,               # Protocolo (ICMP)
        checksum,               # Checksum (0 por hora)
        src_ip,                 # IP de origem
        dest_ip                 # IP de destino
    )

    # Calcula o checksum do cabecalho IP
    checksum = calcula_checksum(header)

    # Recria o cabecalho com o checksum correto
    header = struct.pack(
        version_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment_offset,
        ttl,
        protocol,
        checksum,               # Checksum calculado
        src_ip,
        dest_ip
    )

    return header

def cria_pacote_icmp(identificador:int , sequencia:int) -> bytes:
    """
    Cria o cabeçalho ICMP Echo Request.
    
    Args:
        identificador (int): Identificador único do pacote ICMP.
        sequencia (int): Número de sequência do pacote ICMP.
    
    Returns:
        bytes: Pacote ICMP formatado.
    """
    tipo = 8 # Echo request
    codigo = 0 # Codigo padrao
    checksum = 0 # Inicialmente 0

    header = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, sequencia)
    payload = b"Looking for active hosts..."

    # Calcula checksum do ICMP + payload
    checksum = calcula_checksum(header + payload)

    # Recria o cabecalho ICMP com o checksum correto
    header = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, sequencia)

    return header + payload

def cria_cabecalho_arp(mac_orig: str, ip_orig: str, mac_dest: str = "00:00:00:00:00:00", ip_dest: str = "0.0.0.0", operacao: int = 1) -> bytes:
    """
    Cria o cabeçalho ARP.

    Args:
        mac_origem (str): Endereço MAC de origem.
        ip_origem (str): Endereço IP de origem.
        mac_destino (str): Endereço MAC de destino. Padrão: "00:00:00:00:00:00".
        ip_dest (str): Endereço IP de destino. Padrão: "0.0.0.0".
        operacao (int): Tipo de operação ARP (1 = Request, 2 = Reply). Padrão: 1 (Request).

    Returns:
        bytes: Cabeçalho ARP em bytes.
    """
    htype = struct.pack("!H", 1)            # Tipo de hardware: Ethernet (1)
    ptype = struct.pack("!H", 0x0800)       # Tipo de protocolo: IPv4 (0x0800)
    hlen = struct.pack("!B", 6)             # Comprimento do endereço de hardware: 6 bytes
    plen = struct.pack("!B", 4)             # Comprimento do endereço de protocolo: 4 bytes
    operacao = struct.pack("!H", operacao)  # Operação ARP (1 = Request, 2 = Reply)

    try:
        # Converte endereços MAC e IP para bytes
        mac_origem_bytes = bytes.fromhex(mac_orig.replace(":", ""))
        ip_origem_bytes = socket.inet_aton(ip_orig)
        mac_destino_bytes = bytes.fromhex(mac_dest.replace(":", ""))
        ip_destino_bytes = socket.inet_aton(ip_dest)

        # Monta o cabeçalho ARP
        cabecalho = (
            htype +
            ptype +
            hlen +
            plen +
            operacao +
            mac_origem_bytes +
            ip_origem_bytes +
            mac_destino_bytes +
            ip_destino_bytes
        )

        return cabecalho
    except Exception as e:
        # print(f"[DEBUG] ERRO NO CRIA CABECALHO ARP: {e}")
        pass

def monta_pacote(mac_orig: str, mac_dest: str, ip_orig: str, ip_dest: str) -> bytes:
    """
    Monta o pacote completo (Ethernet + IP + ICMP).

    Args:
        mac_origem (str): Endereço MAC de origem.
        mac_destino (str): Endereço MAC de destino.
        ip_origem (str): Endereço IP de origem.
        ip_destino (str): Endereço IP de destino.

    Returns:
        bytes: Pacote completo para envio.
    """
    # Cria os cabecalhos
    ethernet_header = cria_cabecalho_ethernet(mac_dest = mac_dest, mac_orig = mac_orig, protocol = 0x0800)
    icmp_header = cria_pacote_icmp(identificador = 1, sequencia = 1)
    ip_header = cria_cabecalho_ip(ip_orig = ip_orig, ip_dest = ip_dest, payload_length=len(icmp_header))

    # Combina camadas
    pacote = ethernet_header + ip_header + icmp_header

    return pacote

def enviar_pacote(pacote: bytes, interface: str, timeout: float) -> tuple:
    """
    Envia o pacote pela interface de rede com um tempo limite para resposta.

    Args:
        pacote (bytes): Pacote completo (Ethernet + IP + ICMP).
        interface (str): Nome da interface de rede (ex.: "eth0").
        timeout (float): Tempo limite para esperar por uma resposta, em segundos.

    Returns:
        dict: Resposta recebida e o timestamp de envio.

    Raises:
        TimeoutError: Se nenhuma resposta for recebida dentro do limite de tempo.
    """
    try:
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        raw_socket.bind((interface, 0))
        raw_socket.settimeout(timeout)

        # Envia pacote e guarda tempo inicial
        inicio = time.time()
        raw_socket.send(pacote)

        try:
            resposta, _ = raw_socket.recvfrom(65535)
            fim = time.time()

            tempo_resposta = (fim - inicio) * 1000

            return resposta, tempo_resposta
        except socket.timeout:
            raise TimeoutError("Nenhuma resposta recebida dentro do limite de tempo.")

    except PermissionError:
        print("Erro: Script sem permissao. Rode como administrador")
    except Exception as e:
        print(f"Erro ao enviar o pacote: {e}")
    
    return None, None

def arp_request(ip_dest: str, interface: str, ip_orig: str, mac_orig: str, timeout: float = 1.0) -> str:
    """
    Resolve o MAC de um endereço IP utilizando ARP.

    Args:
        ip_dest (str): Endereço IP de destino.
        interface (str): Interface de rede.
        ip_orig (str): Endereço IP de origem.
        mac_orig (str): Endereço MAC de origem.
        timeout (float): Tempo limite para aguardar a resposta ARP.

    Returns:
        str: Endereço MAC do IP de destino.

    Raises:
        ValueError: Se o MAC não for resolvido.
    """
    # print(f"[DEBUG] Resolvendo MAC para {ip_dest} na interface {interface}")
    # Verifica o cache
    cache = load_arp_cache()
    if ip_dest in cache:
        # print(f"[DEBUG] MAC encontrado no cache: {cache[ip_dest]}")
        return cache[ip_dest]

    # print(f"[DEBUG] Enviando ARP request para {ip_dest}")

    # Cabecalho ethernet
    mac_broadcast = "ff:ff:ff:ff:ff:ff"
    ethertype_arp = 0x0806 # ARP protocol
    ethernet_header = cria_cabecalho_ethernet(mac_dest=mac_broadcast, mac_orig=mac_orig, protocol=ethertype_arp)

    # Cabecalho ARP
    arp_payload = cria_cabecalho_arp(mac_orig=mac_orig, ip_orig=ip_orig, ip_dest=ip_dest, operacao=1)

    # Pacote completo
    pacote = ethernet_header + arp_payload

    # Envia o pacote e espera a resposta
    resposta, _ = enviar_pacote(pacote=pacote, interface=interface, timeout=1000)

    # Verificar a resposta e extrair o MAC de destino
    if resposta:
        mac_dest = resposta[6:12].hex(":")  # Extrair os 6 bytes do MAC
        # print(f"[DEBUG] MAC de destino resolvido: {mac_dest}")
        cache[ip_dest] = mac_dest
        save_arp_cache(cache)
        return mac_dest

    raise ValueError(f"Não foi possível resolver o MAC para {ip_dest}")

def scan_host(endereco_ip_host: str, timeout: int, interface: str, mac_orig: str, ip_orig: str) -> tuple:
    """
    Realiza o escaneamento de um único host na rede, enviando pacotes ICMP encapsulados em Ethernet
    e, quando necessário, resolvendo o endereço MAC de destino utilizando ARP.

    O método:
        1. Resolve o endereço MAC de destino utilizando ARP, se o MAC não for conhecido.
        2. Monta um pacote Ethernet + IP + ICMP para envio.
        3. Envia o pacote e aguarda uma resposta dentro do tempo limite.
        4. Retorna o IP e o tempo de resposta (RTT) caso o host responda, ou None se não houver resposta.

    Args:
        endereco_ip_host (str): Endereço IP do host a ser escaneado.
        timeout (int): Tempo limite para aguardar resposta, em milissegundos.
        interface (str): Nome da interface de rede utilizada para envio (ex.: "eth0").
        mac_orig (str): Endereço MAC de origem (associado à interface de rede).
        ip_orig (str): Endereço IP de origem (associado à interface de rede).

    Returns:
        tuple:
            - str: Endereço IP do host escaneado (ex.: "192.168.1.1").
            - float: Tempo de resposta (RTT) em milissegundos, se o host responder.
        None:
            Retorna None se não houver resposta do host dentro do tempo limite.

    Raises:
        TimeoutError: Se o tempo limite para resposta for atingido.
        ValueError: Se ocorrer um erro ao resolver o MAC de destino.
        Exception: Para quaisquer outros erros encontrados durante o escaneamento.
    """
    # print(f"[DEBUG] Iniciando scan_host para {endereco_ip_host} com timeout de {timeout}ms")

    try:
        # Tentar resolver o MAC do destino
        # print(f"[DEBUG] Tentando resolver o MAC para {endereco_ip_host}")
        try:
            mac_dest = arp_request(
                ip_dest=endereco_ip_host, 
                interface=interface, 
                ip_orig=ip_orig, 
                mac_orig=mac_orig
            )
            # print(f"[DEBUG] MAC resolvido: {mac_dest}")
        except ValueError:
            raise TimeoutError(f"{endereco_ip_host} é inalcancavel")

        # print(f"[DEBUG] Montando pacote para {endereco_ip_host}")
        # Monta pacote completo
        pacote = monta_pacote(mac_orig=mac_orig, mac_dest=mac_dest, ip_orig=ip_orig, ip_dest=endereco_ip_host)

        # print(f"[DEBUG] Enviando pacote para {endereco_ip_host}")
        # Envia o pacote
        resposta, tempo_resposta = enviar_pacote(pacote=pacote, interface=interface, timeout=timeout / 1000.0)
        
        if resposta:
            # print(f"[DEBUG] Resposta recebida de {endereco_ip_host} em {tempo_resposta:.2f}ms")
            # Verifica se resposta é Echo Reply (ICMP tipo 0)
            if resposta[20:22] == b'\x00\x00':
                return endereco_ip_host, tempo_resposta
    except TimeoutError:
        # print(f"[DEBUG] Timeout ao escanear {endereco_ip_host}")
        pass
    except Exception as e:
        # print(f"[DEBUG] Erro ao escanear {endereco_ip_host}: {e}")
        pass

    return None

def thread_scan(host: str, timeout: int, active_hosts: list, lock: threading.Lock, mac_orig: str, ip_orig: str) -> None:
    """
    Realiza o escaneamento de um host em uma thread separada e armazena o resultado de forma segura.

    Args:
        host (str): Endereco IP do host a ser escaneado.
        timeout (int): Tempo limite para resposta em milissegundos.
        active_hosts (list): Lista compartilhada para armazenar os resultados dos hosts ativos.
        lock (threading.Lock): Lock para garantir acesso seguro a active_hosts.
        mac_orig (str): Endereço MAC de origem.
        ip_orig (str): Endereço IP de origem.

    Returns:
        None
    """
    result = scan_host(endereco_ip_host=host, timeout=timeout, interface="eth0", mac_orig=mac_orig, ip_orig=ip_orig)
    if result:
        with lock:
            active_hosts.append(result)

def scan_all_hosts(ip_range: str, timeout: int, mac_orig: str, ip_orig: str) -> list:
    """
    Varre todos os enderecos IP em um intervalo especificado, verificando quais hosts estao ativos.

    Args:
        ip_range (str): Intervalo de IPs no formato CIDR (ex.: "192.168.1.0/24").
        timeout (int): Tempo limite para cada varredura em milissegundos.
        mac_orig (str): Endereço MAC de origem.
        ip_orig (str): Endereço IP de origem.

    Returns:
        list: Lista de hosts ativos, cada um representado por uma tupla com IP e tempo de resposta.
    """
    threads = []
    active_hosts = []
    lock = threading.Lock()
    hosts = lista_enderecos(ip_range=ip_range)

    for host in hosts:
        thread = threading.Thread(target=thread_scan, args=(host, timeout, active_hosts, lock, mac_orig, ip_orig))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return active_hosts

def main():
    """
    Função principal que coordena a execução do programa de varredura de rede.

    Essa função:
        1. Determina o intervalo de IPs e o timeout fornecidos como argumentos.
        2. Obtém os endereços IP e MAC de origem.
        3. Realiza a varredura de todos os hosts no intervalo fornecido, identificando hosts ativos.
        4. Exibe os resultados da varredura, incluindo os tempos de resposta dos hosts ativos.
        5. Calcula e exibe o tempo total de execução da varredura.

    Args:
        None

    Returns:
        None

    Raises:
        ValueError: Se não for possível determinar o IP ou MAC de origem.
    """
    start_time()

    ip_range = args.ip
    timeout = int(args.timeout)

    print(ip_range)
    print(f"{timeout}ms\n")

    try:
        print("[DEBUG] Obtendo IP e MAC de origem")
        ip_orig, mac_orig = obtem_endr_orig(ip_dest=ip_range.split('/')[0])
        print(f"IP origem: {ip_orig}\nMAC origem: {mac_orig}")
    except ValueError as e:
        print(f"Erro ao determinar IP/MAC de origem: {e}")
        exit(1)

    print("[DEBUG] Iniciando varredura de todos os hosts")
    active_hosts = scan_all_hosts(ip_range=ip_range, timeout=timeout, mac_orig=mac_orig, ip_orig=ip_orig)

    stop_time()

    imprime_enderecos(active_hosts=active_hosts)

    total_hosts = len(lista_enderecos(ip_range))
    print(f"\nNúmero total de máquinas na rede: {total_hosts}")
    print(f"Número de máquinas ativas: {len(active_hosts)}")
    print(f"Tempo total de varredura: {formatar_tempo(total_runtime)}s\n")

main()