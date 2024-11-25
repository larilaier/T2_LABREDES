import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import json
import os
import socket
import struct
import threading
import time
import uuid

parser = argparse.ArgumentParser(description="T2 Lab Redes")
parser.add_argument("ip", nargs="?", default="10.32.143.0/24", help="Endereco IP e Mascara. ex: 10.32.143.0/24")
parser.add_argument("timeout", nargs="?", default="500", help="Tempo limite de execucao em milisegundos")
args = parser.parse_args()

arp_cache_file = "arp_cache.json"
arp_cache = None

interface = ''
totl_init_time = 0
total_end_time = 0
total_runtime = 0

def start_time() -> None:
    """
    Inicia a contagem de tempo para medir a duracao da execucao do programa.
    
    Essa funcao registra o tempo atual em uma variavel global (totl_init_time),
    permitindo calcular a duracao total da execucao posteriormente.
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
        try:
            with open(arp_cache_file, "r") as f:
                cache = json.load(f)
            return cache
        except json.JSONDecodeError as e:
            # print(f"[DEBUG] Erro ao carregar cache ARP: {e}. Limpando cache.")
            os.remove(arp_cache_file)
            return {}
        except Exception as e:
            # print(f"[DEBUG] Erro inesperado ao carregar cache ARP: {e}")
            return {}
    return {}

def save_arp_cache(cache: dict) -> None:
    """
    Salva o cache ARP em um arquivo local.

    Args:
        cache (dict): Cache ARP no formato {IP: MAC}.
    """
    try:
        with open(arp_cache_file, "w") as f:
            json.dump(cache, f, indent=4)
        # print("[DEBUG] Cache ARP salvo com sucesso.")
    except Exception as e:
        # print(f"[DEBUG] Erro ao salvar cache ARP: {e}")
        pass

def imprime_enderecos(active_hosts: list, total_hosts: int) -> None:
    """
    Exibe os enderecos IPv4 e tempos de resposta dos hosts ativos.

    Args:
        active_hosts (list): Lista de tuplas contendo o IP do host (str) e o tempo de resposta (float).
        total_hosts (int): Total de hosts varridos.

    Returns:
        None
    """
    print("\nHosts ativos encontrados:")
    for host in active_hosts:
        print(f"IPv4: {host[0]}, Response time: {host[1]:.2f} ms")

    print(f"\nNúmero total de maquinas na rede: {total_hosts}")
    print(f"Número de maquinas ativas: {len(active_hosts)}")

def is_valid_mac(mac: str) -> bool:
    """
    Valida se o endereco MAC e plausivel e nao e broadcast ou de roteadores.

    Args:
        mac (str): Endereco MAC no formato "AA:BB:CC:DD:EE:FF".

    Returns:
        bool: True se o MAC for valido, False caso contrario.
    """
    invalid_macs = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}
    return mac not in invalid_macs

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

def obtem_interface():
    """
    Retorna a interface de rede conectada ao gateway padrao.
    """
    try:
        with os.popen("ip route | grep default") as route_info:
            default_route = route_info.read().strip()
        if not default_route:
            raise RuntimeError("Nenhuma rota padrao encontrada.")
        
        # Extraindo o nome da interface
        parts = default_route.split()
        interface = parts[parts.index("dev") + 1] if "dev" in parts else None

        # Validando se a interface existe
        if not interface or not os.path.exists(f"/sys/class/net/{interface}"):
            raise RuntimeError(f"Interface detectada ({interface}) nao e valida.")
        
        return interface
    except Exception as e:
        print(f"Erro ao obter interface ativa: {e}")
        return None

def obtem_endr_orig(ip_dest: str) -> tuple:
    """
    Obtem o endereco IP e MAC da propria maquina.

    Args:
        ip_dest (str): Endereco IP de destino (nao usado para determinar o MAC local, mas necessario para logica do socket).

    Returns:
        tuple: IP de origem (str), MAC de origem (str).

    Raises:
        ValueError: Se nao for possivel determinar os enderecos.
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

    O checksum e calculado somando todas as palavras de 16 bits (2 bytes consecutivos)
    do pacote. Se o número total de bytes for impar, o último byte e tratado como
    se estivesse acompanhado de um byte 0. Apos a soma, o resultado e ajustado para
    caber em 16 bits e complementado bit a bit.

    Args:
        data (bytes): Dados do pacote ICMP.

    Returns:
        int: Checksum calculado.
    """
    soma = 0
    n = len(data)

    for i in range(0, n, 2):
        # Processa dois bytes por vez; adiciona 0 ao último byte se for impar
        if i + 1 < n:
            plvr_16bits = (data[i] << 8) + data[i + 1]
        else:
            plvr_16bits = (data[i] << 8)  # Último byte com complemento 0
        soma += plvr_16bits

        # Ajusta para 16 bits
        soma = (soma & 0xFFFF) + (soma >> 16)

    # Complementa o checksum
    checksum = ~soma & 0xFFFF
    return checksum

def cria_cabecalho_ethernet(mac_dest: str, mac_orig: str, protocol: int) -> bytes:
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
        if not mac_dest or not mac_orig:
            raise ValueError("MAC de origem ou destino invalido.")

        mac_dest_bytes = bytes.fromhex(mac_dest.replace(':', ''))
        mac_orig_bytes = bytes.fromhex(mac_orig.replace(':', ''))

        ethernet_header = struct.pack(
            "!6s6sH",
            mac_dest_bytes,
            mac_orig_bytes,
            protocol
        )
        # print(f"[DEBUG] Ethernet Header: {ethernet_header.hex()}")
        return ethernet_header
    except Exception as e:
        # print(f"[ERRO] ERRO NO CRIA CABEcALHO ETHERNET: {e}")
        return None

def cria_cabecalho_ip(ip_orig: str, ip_dest: str, payload_length: int) -> bytes:
    """
    Cria o cabecalho IP.

    Args:
        ip_orig (str): Endereco IP de origem.
        ip_dest (str): Endereco IP de destino.
        payload_length (int): Tamanho do payload.

    Returns:
        bytes: Cabecalho IP formatado.
    """ 
    try:
        version_ihl = (4 << 4) | 5  # Versao IPv4 e IHL = 5 palavras (20 bytes)
        dscp_ecn = 0  # Tipo de servico
        total_length = 20 + payload_length  # Tamanho total do pacote IP
        identification = 54321  # Identificacao do pacote
        flags_fragment_offset = 0  # Sem fragmentacao
        ttl = 64  # Time to live
        protocol = 1  # ICMP
        checksum = 0  # Inicialmente 0 para o calculo
        src_ip = socket.inet_aton(ip_orig)
        dest_ip = socket.inet_aton(ip_dest)

        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip,
            dest_ip
        )

        checksum = calcula_checksum(header)

        header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip,
            dest_ip
        )
        # print(f"[DEBUG] IP Header: {header.hex()}")
        return header
    except Exception as e:
        # print(f"[ERRO] Falha ao criar cabecalho IP: {e}")
        return None

def cria_pacote_icmp(identificador: int, sequencia: int) -> bytes:
    """
    Cria o cabecalho ICMP Echo Request.

    Args:
        identificador (int): Identificador único do pacote ICMP.
        sequencia (int): Número de sequência do pacote ICMP.

    Returns:
        bytes: Pacote ICMP formatado.
    """
    try:
        tipo = 8  # Echo request
        codigo = 0  # Codigo padrao
        checksum = 0  # Inicialmente 0

        # Cabecalho inicial com checksum zero
        header = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, sequencia)
        payload = b"Looking for active hosts..."  # Mensagem de teste no payload

        # Calcula o checksum do cabecalho e do payload
        checksum = calcula_checksum(header + payload)

        # Recria o cabecalho com o checksum correto
        header = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, sequencia)

        pacote = header + payload
        # print(f"[DEBUG] ICMP Header: {header.hex()}")
        # print(f"[DEBUG] ICMP Payload: {payload.hex()}")
        # print(f"[DEBUG] ICMP Packet: {pacote.hex()}")
        return pacote
    except Exception as e:
        # print(f"[ERRO] Falha ao criar cabecalho ICMP: {e}")
        return None

def cria_cabecalho_arp(mac_orig: str, ip_orig: str, mac_dest: str = "00:00:00:00:00:00", ip_dest: str = "0.0.0.0", operacao: int = 1) -> bytes:
    """
    Cria o cabecalho ARP.

    Args:
        mac_origem (str): Endereco MAC de origem.
        ip_origem (str): Endereco IP de origem.
        mac_destino (str): Endereco MAC de destino. Padrao: "00:00:00:00:00:00".
        ip_dest (str): Endereco IP de destino. Padrao: "0.0.0.0".
        operacao (int): Tipo de operacao ARP (1 = Request, 2 = Reply). Padrao: 1 (Request).

    Returns:
        bytes: Cabecalho ARP em bytes.
    """
    try:
        htype = struct.pack("!H", 1)            # Tipo de hardware: Ethernet (1)
        ptype = struct.pack("!H", 0x0800)       # Tipo de protocolo: IPv4 (0x0800)
        hlen = struct.pack("!B", 6)             # Comprimento do endereco de hardware: 6 bytes
        plen = struct.pack("!B", 4)             # Comprimento do endereco de protocolo: 4 bytes
        operacao = struct.pack("!H", operacao)  # Operacao ARP (1 = Request, 2 = Reply)

        # Converte enderecos MAC e IP para bytes
        mac_origem_bytes = bytes.fromhex(mac_orig.replace(":", ""))
        ip_origem_bytes = socket.inet_aton(ip_orig)
        mac_destino_bytes = bytes.fromhex(mac_dest.replace(":", ""))
        ip_destino_bytes = socket.inet_aton(ip_dest)

        # Monta o cabecalho ARP
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
        print(f"[ERRO] ERRO NO CABEcALHO ARP: {e}")
        raise

def monta_pacote(mac_orig: str, mac_dest: str, ip_orig: str, ip_dest: str) -> bytes:
    """
    Monta o pacote completo (Ethernet + IP + ICMP).

    Args:
        mac_orig (str): Endereco MAC de origem.
        mac_dest (str): Endereco MAC de destino.
        ip_orig (str): Endereco IP de origem.
        ip_dest (str): Endereco IP de destino.

    Returns:
        bytes: Pacote completo para envio, ou None em caso de erro.
    """
    try:
        if not is_valid_mac(mac_orig) or not is_valid_mac(mac_dest):
            raise ValueError("Enderecos MAC invalidos.")
        if not ip_orig or not ip_dest:
            raise ValueError("Enderecos IP invalidos.")

        ethernet_header = cria_cabecalho_ethernet(mac_dest, mac_orig, 0x0800)
        if not ethernet_header:
            raise ValueError("Falha ao criar cabecalho Ethernet.")
        # print(f"[DEBUG] Cabecalho Ethernet: {ethernet_header.hex()}")

        icmp_header = cria_pacote_icmp(1, 1)
        if not icmp_header:
            raise ValueError("Falha ao criar cabecalho ICMP.")
        # print(f"[DEBUG] Cabecalho ICMP: {icmp_header.hex()}")

        ip_header = cria_cabecalho_ip(ip_orig, ip_dest, len(icmp_header))
        if not ip_header:
            raise ValueError("Falha ao criar cabecalho IP.")
        # print(f"[DEBUG] Cabecalho IP: {ip_header.hex()}")

        pacote = ethernet_header + ip_header + icmp_header
        # print(f"[DEBUG] Pacote completo (Ethernet+IP+ICMP): {pacote.hex()}")
        return pacote
    except Exception as e:
        # print(f"[ERRO] Falha ao montar pacote: {e}")
        return None

def enviar_pacote(pacote: bytes, interface: str, timeout: float) -> tuple:
    """
    Envia um pacote e aguarda uma resposta pela interface especificada.

    Args:
        pacote (bytes): Pacote a ser enviado.
        interface (str): Interface de rede utilizada.
        timeout (float): Tempo limite para aguardar resposta (em segundos).

    Returns:
        tuple: (resposta, tempo de resposta em milissegundos), ou (None, None) em caso de falha.
    """
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806)) as raw_socket:
            raw_socket.bind((interface, 0))
            raw_socket.settimeout(timeout)

            inicio = time.time()
            raw_socket.send(pacote)
            # print(f"[DEBUG] Pacote enviado para {interface}, timeout: {timeout}s")

            try:
                resposta, _ = raw_socket.recvfrom(65535)
                rtt = (time.time() - inicio) * 1000
                # print(f"[DEBUG] Resposta recebida em {rtt:.2f} ms")
                return resposta, rtt
            except socket.timeout:
                # print("[DEBUG] Timeout alcancado sem resposta.")
                return None, None
    except Exception as e:
        # print(f"[ERRO] Falha no envio ou recepcao: {e}")
        return None, None

def arp_request(ip_dest: str, interface: str, ip_orig: str, mac_orig: str, timeout: float = 1.0) -> str:
    """
    Resolve o endereco MAC para o IP de destino utilizando ARP.

    Args:
        ip_dest (str): Endereco IP do destino.
        interface (str): Interface de rede.
        ip_orig (str): Endereco IP de origem.
        mac_orig (str): Endereco MAC de origem.
        timeout (float): Tempo limite para aguardar resposta em segundos.

    Returns:
        str: Endereco MAC do IP de destino, ou None se a resolucao falhar.
    """
    global arp_cache

    # Verificar se o MAC esta no cache
    if ip_dest in arp_cache:
        mac_dest = arp_cache[ip_dest]
        # print(f"[DEBUG] MAC encontrado no cache ARP para {ip_dest}: {mac_dest}")
        return mac_dest

    try:
        pacote = cria_cabecalho_arp(mac_orig, ip_orig, "00:00:00:00:00:00", ip_dest, 1)
        resposta, _ = enviar_pacote(pacote, interface, timeout)

        if resposta and len(resposta) >= 12:  # Verifique se ha dados suficientes
            mac_dest = ':'.join(f"{b:02x}" for b in resposta[6:12])
            if not is_valid_mac(mac_dest):
                # print(f"[ALERTA] MAC invalido detectado para {ip_dest}: {mac_dest}")
                return None
            # print(f"[DEBUG] MAC resolvido para {ip_dest}: {mac_dest}")

            # Salvar no cache ARP
            arp_cache[ip_dest] = mac_dest
            save_arp_cache(arp_cache)
            return mac_dest
        else:
            # print(f"[DEBUG] Nenhuma resposta ARP valida recebida para {ip_dest}")
            return None
    except Exception as e:
        # print(f"[ERRO] Falha no ARP Request para {ip_dest}: {e}")
        return None

def scan_host(endereco_ip_host: str, timeout: int, interface: str, mac_orig: str, ip_orig: str) -> tuple:
    """
    Escaneia um único host na rede.

    Args:
        endereco_ip_host (str): Endereco IP do host a ser escaneado.
        timeout (int): Tempo limite para o scan em milissegundos.
        interface (str): Interface de rede utilizada.
        mac_orig (str): Endereco MAC de origem.
        ip_orig (str): Endereco IP de origem.

    Returns:
        tuple: (IP do host ativo, tempo de resposta em milissegundos) ou None.
    """
    try:
        # Proteger acesso ao cache ARP
        with threading.Lock():
            mac_dest = arp_request(endereco_ip_host, interface, ip_orig, mac_orig, timeout / 1000)

        if not mac_dest:
            # print(f"[DEBUG] Nao foi possivel resolver o MAC para {endereco_ip_host}.")
            return None

        pacote = monta_pacote(mac_orig, mac_dest, ip_orig, endereco_ip_host)
        if not pacote:
            # print(f"[DEBUG] Pacote invalido para {endereco_ip_host}.")
            return None

        resposta, rtt = enviar_pacote(pacote, interface, timeout / 1000)

        if resposta:
            # print(f"[DEBUG] Host {endereco_ip_host} respondeu em {rtt:.2f}ms")
            return endereco_ip_host, rtt
        else:
            # print(f"[DEBUG] Nenhuma resposta de {endereco_ip_host}")
            return None
    except Exception as e:
        # print(f"[ERRO] Falha ao escanear {endereco_ip_host}: {e}")
        return None
    
def thread_scan(host: str, timeout: int, active_hosts: list, lock: threading.Lock, mac_orig: str, ip_orig: str, interface: str) -> None:
    """
    Executa o escaneamento de um host dentro de uma thread.

    Args:
        host (str): Endereco IP do host a ser escaneado.
        timeout (int): Tempo limite em milissegundos.
        active_hosts (list): Lista compartilhada de hosts ativos.
        lock (threading.Lock): Lock para acesso sincronizado a lista.
        mac_orig (str): Endereco MAC de origem.
        ip_orig (str): Endereco IP de origem.
        interface (str): Interface de rede usada.

    Returns:
        None
    """
    inicio = time.time()
    try:
        # print(f"[DEBUG] Iniciando escaneamento para {host}")
        result = scan_host(host, timeout, interface, mac_orig, ip_orig)
        if result:
            with lock:
                active_hosts.append(result)
    except Exception as e:
        # print(f"[ERRO] Falha ao escanear {host}: {e}")
        pass
    finally:
        fim = time.time()
        # print(f"[DEBUG] Thread finalizada para {host}, tempo decorrido: {fim - inicio:.2f}s")

def scan_all_hosts(ip_range: str, timeout: int, mac_orig: str, ip_orig: str, interface: str) -> list:
    """
    Realiza a varredura de todos os enderecos IP em um intervalo fornecido.

    A funcao utiliza multithreading para otimizar a varredura. Cada endereco IP e escaneado
    com ARP e ICMP para verificar a disponibilidade do host.

    Args:
        ip_range (str): Intervalo de IPs no formato CIDR (ex.: "192.168.1.0/24").
        timeout (int): Tempo limite para cada tentativa de varredura em milissegundos.
        mac_orig (str): Endereco MAC da maquina de origem.
        ip_orig (str): Endereco IP da maquina de origem.
        interface (str): Interface de rede utilizada.

    Returns:
        list: Lista de tuplas contendo:
            - Endereco IP ativo (str).
            - Tempo de resposta em milissegundos (float).
    """
    active_hosts = []
    lock = threading.Lock()
    hosts = lista_enderecos(ip_range)

    # print(f"[DEBUG] Iniciando varredura de {len(hosts)} hosts...")

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [
            executor.submit(thread_scan, host, timeout, active_hosts, lock, mac_orig, ip_orig, interface)
            for host in hosts
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                # print(f"[ERRO] Falha na execucao de thread: {e}")
                pass

    # print(f"[DEBUG] Varredura concluida. {len(active_hosts)} hosts ativos encontrados.")
    return active_hosts

def main():
    """
    Funcao principal que coordena a execucao do programa de varredura de rede.

    Esta funcao:
        1. Carrega o cache ARP salvo anteriormente, se disponivel.
        2. Determina a interface de rede conectada ao gateway padrao.
        3. Obtem os enderecos IP e MAC da maquina de origem.
        4. Realiza a varredura de todos os hosts no intervalo fornecido.
        5. Exibe os resultados da varredura, incluindo:
           - Hosts ativos com tempos de resposta.
           - Número total de maquinas na rede e número de maquinas ativas.
           - Tempo total de execucao da varredura.
        6. Atualiza e salva o cache ARP ao termino.

    Args:
        None

    Returns:
        None
    """
    global interface, arp_cache
    start_time()

    # Carregar o cache ARP
    arp_cache = load_arp_cache()

    ip_range = args.ip
    timeout = int(args.timeout)

    interface = obtem_interface()
    if not interface:
        print("Erro: Nenhuma interface ativa encontrada.")
        exit(1)
    # print(f"[DEBUG] Interface detectada: {interface}")

    print(f"Usando a interface: {interface}")
    print(ip_range)
    print(f"{timeout}ms\n")

    try:
        # print("[DEBUG] Obtendo IP e MAC de origem")
        ip_orig, mac_orig = obtem_endr_orig(ip_dest=ip_range.split('/')[0])
        print(f"IP origem: {ip_orig}\nMAC origem: {mac_orig}")
    except ValueError as e:
        print(f"Erro ao determinar IP/MAC de origem: {e}")
        exit(1)

    # print("[DEBUG] Iniciando varredura de todos os hosts")
    active_hosts = scan_all_hosts(ip_range=ip_range, timeout=timeout, mac_orig=mac_orig, ip_orig=ip_orig, interface=interface)

    stop_time()

    imprime_enderecos(active_hosts=active_hosts, total_hosts=len(lista_enderecos(ip_range)))

    print(f"Tempo total de varredura: {formatar_tempo(total_runtime)}s\n")

    # Salvar o cache ARP ao termino da execucao
    save_arp_cache(arp_cache)

if __name__ == "__main__":
    main()