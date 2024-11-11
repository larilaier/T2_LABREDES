# T2_LABREDES
Trabalho Final
Objetivo
Desenvolver um ataque man-in-the-middle para capturar o histórico de navegação web
de um computador alvo remoto. O projeto será conduzido em três etapas principais:
● Descoberta de hosts: Desenvolver uma aplicação para identificar hosts ativos
na rede, realizando uma varredura inicial semelhante a um ping scan para
mapear os dispositivos conectados.
● Execução do ataque: Após identificar o host alvo (um dos hosts ativos na rede),
realizar um ataque de ARP Spoofing com man-in-the-middle utilizando a
ferramenta arpspoof, inserindo-se no fluxo de comunicação entre o alvo e o
roteador.
● Monitoramento de tráfego: Criar uma aplicação para monitorar o tráfego de
navegação web do host alvo, capturando pacotes HTTP e DNS para rastrear o
histórico de navegação.
Descrição
Usando um programa sniffer como o Wireshark, é possível monitorar todo o tráfego de
rede de um host e analisar seu conteúdo. Por exemplo, ao inspecionar pacotes dos
protocolos DNS e HTTP, é possível reconstruir o histórico de navegação web de um
dispositivo. Contudo, essa prática geralmente exige acesso físico ao host. Para realizar
esse monitoramento remotamente em outros dispositivos de uma rede local, pode-se
recorrer a um ataque man-in-the-middle, explorando vulnerabilidades comuns em
redes locais.
Neste trabalho, utilizaremos um ataque de ARP Spoofing para interceptar o tráfego de
rede e monitorar o histórico de navegação web de cada host alvo. A implementação
será dividida em três etapas principais:
● Desenvolvimento da aplicação de varredura: Criação de uma ferramenta para
identificar hosts ativos na rede local (ANEXO I).
● Execução de ARP Spoofing com man-in-the-middle: Configuração de um ataque
que insere o atacante entre o host alvo e o roteador (ANEXO II).
● Desenvolvimento de aplicação de análise de tráfego: Criação de uma ferramenta
para capturar e analisar o histórico de navegação web dos hosts atacados (ANEXO
III).
Observações Gerais
As aplicações implementadas nas etapas 1 e 3 deverão utilizar a API socket
RAW, devendo ser declaradas nos programas as estruturas de dados necessárias
para a manipulação de pacotes ICMP, IP e Ethernet (arquivo header contendo as
definições de tipo). Sua implementação deve ser modular, ou seja, deve ser organizada
de maneira a ser estendida, prevendo a possibilidade de adicionar outros parâmetros,
protocolos e modos de operação.
Resultado e Entrega
Grupo: grupos de até 3 alunos.
Data de entrega: 25/11 no Moodle
Apresentação: 25/11 e 02/12
Observações Gerais: É importante que todos os integrantes dos grupos estejam
aptos a apresentarem o trabalho a partir do início da aula. Para a entrega, é
esperado que apenas um dos integrantes envie pelo Moodle, até a data e hora
especificadas, um arquivo .zip com os nomes dos integrantes, contendo o código
fonte completo do projeto e um relatório descrevendo a implementação e os
testes realizados. É importante que no relatório seja apresentada uma análise,
incluindo o uso de screenshots da ferramenta Wireshark.
IMPORTANTE: Não serão aceitos trabalhos entregues fora do prazo. Trabalhos que
não compilam ou que não executam não serão avaliados. Todos os trabalhos serão
analisados e comparados. Caso seja identificada cópia de trabalhos, todos os trabalhos
envolvidos receberão nota ZERO
