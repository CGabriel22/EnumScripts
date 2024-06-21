# 🤖 Enumeration Scripts
All the scripts you need to enumerate services, protocols, versions, routes, vulnerabilities and more.

The purpose of this repository is to build several scripts to automate information gathering and enumeration in order to facilitate the pentest process and learn how famous pentest tools work, learn how recognition and working with protocols and services work.

## 📜 Table of Contents

- [Script Functionality](#script-functionality)
- [Protocols](#protocols)
- [Services](#services)
  - [Common Services and protocols](#common-services)
- [Ports](#ports)
- [Domains and Subdomains](#domains-and-subdomains)
- [Routes](#routes)
- [How the Scripts Aid in Pentesting](#how-the-scripts-aid-in-pentesting)
- [How to Use the Scripts](#how-to-use-the-scripts)
  - [Clone the Repository](#clone-the-repository)
- [Scripts List](#scripts-list)
  - [Current Scripts](#current-scripts)
  - [Future Scripts](#future-scripts)

## ⚙️ Script Functionality <a name="script-functionality"></a>

Each script in this repository is crafted to perform specific tasks related to network and system reconnaissance. These tasks include, but are not limited to, enumerating users, identifying services running on specific ports, discovering subdomains, and detecting vulnerabilities in protocols and services

## 🌐 Protocolos <a name="protocols"></a>

Um protocolo é um conjunto de regras que governam a comunicação entre dispositivos em uma rede. Protocolos garantem que os dados sejam transmitidos em um formato padronizado, permitindo que dispositivos de diferentes fabricantes e com diferentes sistemas operacionais se comuniquem efetivamente.

## 🛠️ Serviços <a name="services"></a>

Um serviço em redes é uma aplicação ou processo que fornece uma função específica em uma rede. Os serviços são executados em servidores e podem ser acessados por clientes na rede. Serviços comuns incluem servidores web, servidores de e-mail e servidores de transferência de arquivos.

### Serviços e protocolos comuns <a name="common-services"></a>

**Protocolos de Transferência de Dados**

- HTTP (HyperText Transfer Protocol): Porta 80 - Protocolo para transferência de páginas web.
- HTTPS (HyperText Transfer Protocol Secure): Porta 443 - Versão segura do HTTP com criptografia SSL/TLS.
- FTP (File Transfer Protocol): Portas 20 (dados) e 21 (controle) - Protocolo para transferência de arquivos.
- SFTP (SSH File Transfer Protocol): Porta 22 - Protocolo seguro para transferência de arquivos sobre SSH.
- TFTP (Trivial File Transfer Protocol): Porta 69 - Protocolo simples para transferência de arquivos, sem autenticação.
- SCP (Secure Copy Protocol): Porta 22 - Protocolo para cópia segura de arquivos entre hosts.
- SMB (Server Message Block): Portas 139 e 445 - Protocolo para compartilhamento de arquivos e impressoras em redes Windows.
- NFS (Network File System): Porta 2049 - Protocolo para compartilhamento de arquivos em redes Unix/Linux.

**Protocolos de Email**

- SMTP (Simple Mail Transfer Protocol): Porta 25 - Protocolo para envio de emails.
- SMTPS (SMTP Secure): Porta 465 - Versão segura do SMTP com criptografia SSL/TLS.
- IMAP (Internet Message Access Protocol): Porta 143 - Protocolo para acesso a emails em servidores.
- IMAPS (IMAP Secure): Porta 993 - Versão segura do IMAP com criptografia SSL/TLS.
- POP3 (Post Office Protocol 3): Porta 110 - Protocolo para recebimento de emails.
- POP3S (POP3 Secure): Porta 995 - Versão segura do POP3 com criptografia SSL/TLS.

**Protocolos de Rede e Administração**

- DNS (Domain Name System): Porta 53 - Sistema para resolução de nomes de domínio.
- DHCP (Dynamic Host Configuration Protocol): Portas 67 (servidor) e 68 (cliente) - Protocolo para configuração dinâmica de endereços IP.
- SNMP (Simple Network Management Protocol): Portas 161 e 162 - Protocolo para gerenciamento de dispositivos de rede.
- SSH (Secure Shell): Porta 22 - Protocolo para acesso remoto seguro a servidores.
- Telnet: Porta 23 - Protocolo para acesso remoto não seguro a servidores.
- RDP (Remote Desktop Protocol): Porta 3389 - Protocolo para acesso remoto a desktops Windows.
- LDAP (Lightweight Directory Access Protocol): Porta 389 - Protocolo para acesso a diretórios de rede.
- LDAPS (LDAP Secure): Porta 636 - Versão segura do LDAP com criptografia SSL/TLS.
- Kerberos: Porta 88 - Protocolo para autenticação segura de usuários e serviços.

**Protocolos de Banco de Dados**

- MySQL: Porta 3306 - Sistema de gerenciamento de banco de dados relacional.
- PostgreSQL: Porta 5432 - Sistema de gerenciamento de banco de dados relacional avançado.
- MSSQL (Microsoft SQL Server): Porta 1433 - Sistema de gerenciamento de banco de dados da Microsoft.
- Oracle DB: Porta 1521 - Sistema de gerenciamento de banco de dados da Oracle.
- MongoDB: Porta 27017 - Banco de dados NoSQL orientado a documentos.
- Cassandra: Porta 9042 - Banco de dados NoSQL distribuído.
- Redis: Porta 6379 - Banco de dados NoSQL em memória para armazenamento de chave-valor.

**Protocolos de Mensageria e Streaming**

- IRC (Internet Relay Chat): Porta 6667 - Protocolo para comunicação em tempo real via chat.
- XMPP (Extensible Messaging and Presence Protocol): Porta 5222 - Protocolo para mensagens instantâneas e presença online.
- STUN (Session Traversal Utilities for NAT): Porta 3478 - Protocolo para descobrir a presença de NATs e firewalls.
- TURN (Traversal Using Relays around NAT): Porta 3478 - Protocolo para retransmissão de mídia em redes NAT.
- RTP (Real-time Transport Protocol): Portas dinâmicas - Protocolo para transmissão de dados em tempo real, como áudio e vídeo.
- RTSP (Real-Time Streaming Protocol): Porta 554 - Protocolo para controle de streams de mídia.

**Outros Protocolos e Serviços**

- NTP (Network Time Protocol): Porta 123 - Protocolo para sincronização de relógios de computadores.
- Syslog: Porta 514 - Protocolo para envio de mensagens de registro em redes IP.
- OpenVPN: Porta 1194 - Protocolo para criação de redes privadas virtuais (VPN) seguras.
- IKEv2 (Internet Key Exchange version 2): Porta 500 - Protocolo para configuração segura de sessões IPsec.
- L2TP (Layer 2 Tunneling Protocol): Porta 1701 - Protocolo para tunelamento de redes.
- PPTP (Point-to-Point Tunneling Protocol): Porta 1723 - Protocolo para criação de VPNs.
- BGP (Border Gateway Protocol): Porta 179 - Protocolo para roteamento entre sistemas autônomos na internet.
- MQTT (Message Queuing Telemetry Transport): Porta 1883 - Protocolo leve para transporte de mensagens em IoT.
- CoAP (Constrained Application Protocol): Porta 5683 - Protocolo para comunicação em dispositivos restritos na IoT.

## 🔌 Portas <a name="ports"></a>

Portas são pontos finais lógicos em redes, usadas para diferenciar entre diferentes tipos de tráfego de rede. Números de portas padrão são atribuídos a serviços específicos para garantir que o tráfego seja direcionado para a aplicação correta. Por exemplo, HTTP geralmente usa a porta 80, enquanto HTTPS usa a porta 443.

## 🌍 Domínios e Subdomínios <a name="domains-and-subdomains"></a>

- **Domínio:** Um domínio é um nome único que identifica um site na internet, como `example.com`.
- **Subdomínio:** Um subdomínio é uma subdivisão de um domínio que pode ser usado para organizar diferentes seções de um site, como `blog.example.com`.

## 🛤️ Rotas <a name="routes"></a>

Rotas em redes referem-se aos caminhos que os pacotes de dados tomam para chegar ao seu destino. A enumeração adequada de rotas pode revelar a estrutura e a topologia de uma rede, ajudando a entender como os dados fluem dentro dela.

## 🔍 Como os Scripts Ajudam no Pentest <a name="how-the-scripts-aid-in-pentesting"></a>

Os scripts neste repositório automatizam muitas das tarefas tediosas envolvidas em testes de penetração. Automatizando os processos de enumeração e reconhecimento, os pentesters podem reunir informações sobre seus alvos de forma eficiente, identificar possíveis vulnerabilidades e formular estratégias eficazes para testes e exploração adicionais.

## 🚀 Como Usar os Scripts <a name="how-to-use-the-scripts"></a>

Clone o repositório, escolha um script e entre na pasta com o nome do script, por fim siga o readme individual do script.

### Clonar o Repositório <a name="clone-the-repository"></a>

Para clonar o repositório, use o seguinte comando:

```bash
git clone https://github.com/CGabriel22/EnumScripts.git
cd EnumScripts/
```

## 📜 Lista de Scripts <a name="scripts-list"></a>

### Scripts Atuais <a name="current-scripts"></a>

- smtpEnum: Enumera usuários em um servidor SMTP usando o comando VRFY.

### Scripts Futuros <a name="future-scripts"></a>

- Scanner de Portas: Varre por portas abertas em um sistema alvo.
- Encontrador de Subdomínios: Identifica subdomínios associados a um determinado domínio.
- Scanner de Vulnerabilidades: Varre por vulnerabilidades comuns em aplicações web.
- Script de Fingerprinting de Serviços: Identifica serviços e versões executando em portas abertas.
- Ferramenta de Enumeração de Rotas: Mapeia rotas de rede para entender o fluxo de dados.
- DNS Zone Transfer: Tenta realizar uma transferência de zona DNS para obter informações sobre a estrutura da rede.
- SMB Share Enumerator: Lista compartilhamentos de arquivos acessíveis em um servidor SMB.
- SSL/TLS Scanner: Avalia a configuração SSL/TLS de um servidor para detectar fraquezas ou vulnerabilidades.
- Network Route Tracer: Mapeia a rota que os pacotes de dados tomam para chegar a um destino, útil para entender a topologia da rede.
- SNMP Enumerator: Explora informações expostas por dispositivos de rede via SNMP.
- WAF Detector: Detecta a presença de um Web Application Firewall (WAF) e identifica o tipo de WAF em uso.
- Firewall Rule Enumerator: Identifica regras de firewall em uma rede alvo, mapeando portas e serviços permitidos e bloqueados.
- XSS Scanner: Varre aplicações web para detectar vulnerabilidades de Cross-Site Scripting (XSS).
- SQL Injection Tester: Testa parâmetros de entrada de aplicações web para identificar vulnerabilidades de injeção SQL.
- ARP Scanner: Realiza varreduras na rede local usando o protocolo ARP para mapear dispositivos e suas endereços MAC.


