import argparse
import ipaddress
import platform
import re
import socket
import struct
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

def obter_ip_orig(ip_dest: str) -> str:
    """
    Obtém o IP de origem baseado no IP de destino.

    Args:
        ip_dest (str): Endereço IP de destino.

    Returns:
        str: Endereço IP de origem.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((ip_dest, 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception as e:
        raise ValueError(f"Nao foi possivel determinar o IP de origem: {e}")

def obtem_mac_linux(ip_orig: str) -> str:
    """
    Busca o MAC de origem no Linux usando o comando 'ip'.

    Args:
        ip_orig (str): Endereço IP de origem.

    Returns:
        str: Endereço MAC de origem.
    """
    try:
        # Captura output de comando terminal
        output = subprocess.check_output('ip addr show', shell = True, text = True)

        # Busca interface associada ao IP
        interface_match = re.search(rf"\s+inet {ip_orig}.*?scope global (\w+)", output)
        if interface_match:
            interface = interface_match.group(1)

            # Busca MAC associado a interface
            mac_match = re.search(rf"{interface}.*?link/ether ([\w:]+)", output, re.DOTALL)
            if mac_match:
                return mac_match.group(1)
    except Exception as e:
        raise ValueError(f"Erro ao buscar MAC no Linux: {e}")
    return None

def obtem_mac_windows(ip_orig: str) -> str:
    """
    Busca o MAC de origem no Windows usando o comando 'ipconfig'.

    Args:
        ip_orig (str): Endereço IP de origem.

    Returns:
        str: Endereço MAC de origem.

    Raises:
        ValueError: Se não for possível determinar o MAC.
    """
    try:
        # Captura a saída do comando ipconfig com tolerância à decodificação
        output = subprocess.check_output("ipconfig /all", shell=True, text=True, encoding='latin-1', errors='ignore')

        # Divide a saída por adaptadores para buscar o adaptador correto
        adaptadores = output.split("\n\n")
        for adaptador in adaptadores:
            # Verifica se o adaptador contém o IP de origem
            if ip_orig in adaptador:
                # Busca o endereço MAC associado ao adaptador
                mac_match = re.search(r"Endere[oç] F[ií]sico.*?: ([\w-]+)", adaptador, re.IGNORECASE)
                if mac_match:
                    return mac_match.group(1).replace("-", ":")
    except subprocess.CalledProcessError as e:
        raise ValueError(f"Erro ao executar 'ipconfig': {e}")
    except Exception as e:
        raise ValueError(f"Erro ao buscar MAC no Windows: {e}")
    
    raise ValueError("Nao foi possivel determinar o MAC de origem.")

def obtem_mac_macos(ip_orig: str) -> str:
    """
    Busca o MAC de origem no macOS usando o comando 'ifconfig'.

    Args:
        ip_orig (str): Endereço IP de origem.

    Returns:
        str: Endereço MAC de origem.
    """
    try:
        output = subprocess.check_output("ifconfig", shell = True, text = True)

        # Busca o MAC associado ao IP
        interface_match = re.search(rf"inet {ip_orig}.*?flags=.*?\n\s+ether ([\w:]+)", output, re.DOTALL)
        if interface_match:
            return interface_match.group(1)
    except Exception as e:
        raise ValueError(f"Erro ao buscar MAC no macOS: {e}")
    return None

def obter_endr_orig(ip_dest: str) -> tuple:
    """
    Obtém o endereço IP e MAC de origem baseado no sistema operacional.

    Args:
        ip_dest (str): Endereço IP de destino.

    Returns:
        tuple: IP de origem (str), MAC de origem (str).

    Raises:
        ValueError: Se não for possível determinar os endereços.
    """
    ip_orig = obter_ip_orig(ip_dest = ip_dest)
    mac_orig = None

    sys = platform.system()
    try:
        if sys == 'Linux':
            mac_orig = obtem_mac_linux(ip_orig=ip_orig)
        elif sys == 'Windows':
            mac_orig = obtem_mac_windows(ip_orig=ip_orig)
        elif sys == 'Darwin': # macOS
            mac_orig = obtem_mac_macos(ip_orig=ip_orig)
        else:
            raise OSError(f"Sistema operacional '{sys}' nao suportado.")
    except ValueError as e:
        print(f"Erro ao buscar MAC de origem: {e}")
    
    if not mac_orig:
        raise ValueError("Nao foi possivel determinar o MAC de origem.")

    return ip_orig, mac_orig

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
    mac_dest_bytes = bytes.fromhex(mac_dest.replace(':', ''))
    mac_orig_bytes = bytes.fromhex(mac_orig.replace(':', ''))

    ethernet_header = struct.pack(
        "!6s6sH",
        mac_dest_bytes,
        mac_orig_bytes,
        protocol
    )
    return ethernet_header

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

def scan_host(endereco_ip_host: str, timeout: int, interface: str, mac_orig: str, ip_orig: str) -> tuple:
    """
    Realiza um ping em um host especifico enviando um pacote Ethernet + IP + ICMP.

    Args:
        endereco_ip_host (str): Endereco IP do host a ser analisado.
        timeout (int): Tempo limite para resposta, em milissegundos.
        interface (str): Nome da interface de rede (ex.: "eth0").
        mac_orig (str): Endereço MAC de origem.
        ip_orig (str): Endereço IP de origem.

    Returns:
        tuple: Endereco IP e tempo de resposta (se ativo), ou None.
    """
    try:
        # Define MAC de destino (Broadcast por não ser conhecido)
        mac_dest = "ff:ff:ff:ff:ff:ff"

        # Monta pacote completo
        pacote = monta_pacote(mac_orig=mac_orig, mac_dest=mac_dest, ip_orig=ip_orig, ip_dest=endereco_ip_host)

        # Envia o pacote
        resposta, tempo_resposta = enviar_pacote(pacote=pacote, interface=interface, timeout=timeout / 1000.0)
        
        if resposta:
            # Verifica se resposta é Echo Reply (ICMP tipo 0)
            if resposta[20:22] == b'\x00\x00':
                return endereco_ip_host, tempo_resposta
    except TimeoutError:
        # print(f"Host {endereco_ip_host} não respondeu dentro do tempo limite.")
        pass
    except Exception as e:
        # print(f"Erro ao escanear {endereco_ip_host}: {e}")
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
        ip_orig, mac_orig = obter_endr_orig(ip_dest=ip_range.split('/')[0])
        print(f"IP origem: {ip_orig}\nMAC origem: {mac_orig}")
    except ValueError as e:
        print(f"Erro ao determinar IP/MAC de origem: {e}")
        exit(1)

    active_hosts = scan_all_hosts(ip_range=ip_range, timeout=timeout, mac_orig=mac_orig, ip_orig=ip_orig)

    stop_time()

    imprime_enderecos(active_hosts=active_hosts)

    total_hosts = len(lista_enderecos(ip_range))
    print(f"\nNúmero total de máquinas na rede: {total_hosts}")
    print(f"Número de máquinas ativas: {len(active_hosts)}")
    print(f"Tempo total de varredura: {formatar_tempo(total_runtime)}s\n")

main()