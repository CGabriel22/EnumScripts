# 📧 SMTP Enumeration Script

## 📜 Sumário

- [Objetivo](#objetivo)
- [Funcionamento do Script](#funcionamento-do-script)
- [Protocolo SMTP](#protocolo-smtp)
- [Vulnerabilidades do SMTP](#vulnerabilidades-do-smtp)
- [Importância da Segurança no SMTP](#importância-da-segurança-no-smtp)
- [Como o Script Auxilia no Pentest](#como-o-script-auxilia-no-pentest)
- [Como Usar o Script](#como-usar-o-script)
  - [Clonar o Repositório](#clonar-o-repositório)
  - [Executar o Script](#executar-o-script)
- [Futuras Melhorias](#futuras-melhorias)

## 🎯 Objetivo <a name="objetivo"></a>

Este script tem como objetivo enumerar usuários em um servidor SMTP. Ele faz isso enviando comandos `VRFY` para o servidor, que verifica se determinados usuários existem. Esse tipo de script é útil em testes de penetração (pentests) para identificar possíveis contas de e-mail válidas em um servidor.

## 🛠️ Funcionamento do Script <a name="funcionamento-do-script"></a>

1. O script verifica se o número correto de argumentos foi fornecido.
2. Conecta-se ao servidor SMTP especificado.
3. Recebe e exibe a banner do servidor.
4. Lê uma lista de nomes de usuários de um arquivo.
5. Envia comandos `VRFY` para o servidor para cada usuário da lista.
6. Exibe a resposta do servidor para cada comando.
7. Fecha a conexão com o servidor SMTP.

## 📬 Protocolo SMTP <a name="protocolo-smtp"></a>

O Simple Mail Transfer Protocol (SMTP) é um protocolo de comunicação usado para a transmissão de e-mails através da internet. Ele define como as mensagens de e-mail são formatadas, roteadas e entregues aos destinatários. O SMTP opera na porta 25 por padrão.

### Comandos SMTP Comuns

- `HELO`: Identifica o cliente SMTP para o servidor SMTP.
- `MAIL FROM`: Inicia uma transação de e-mail e indica o remetente.
- `RCPT TO`: Especifica o destinatário da mensagem.
- `DATA`: Indica o início dos dados da mensagem.
- `QUIT`: Termina a sessão SMTP.
- `VRFY`: Verifica se um endereço de e-mail existe no servidor.

## 🔓 Vulnerabilidades do SMTP <a name="vulnerabilidades-do-smtp"></a>

Algumas das vulnerabilidades comuns associadas ao SMTP incluem:

- **Open Relay**: Servidores que permitem o envio de e-mails de qualquer origem, facilitando o spam.
- **User Enumeration**: Comandos como `VRFY` e `EXPN` podem ser usados para descobrir endereços de e-mail válidos.
- **Eavesdropping**: A falta de criptografia pode permitir que atacantes interceptem e leiam e-mails.

## 🔐 Importância da Segurança no SMTP <a name="importância-da-segurança-no-smtp"></a>

A segurança no SMTP é crucial para proteger a integridade e a confidencialidade das comunicações por e-mail. Medidas de segurança adequadas podem prevenir ataques de phishing, spam, eavesdropping e outras formas de comprometimento de e-mail. Implementações seguras incluem o uso de criptografia TLS, autenticação robusta e a desativação de comandos inseguros como `VRFY` e `EXPN`.

## 🛡️ Como o Script Auxilia no Pentest <a name="como-o-script-auxilia-no-pentest"></a>

Este script auxilia no processo de pentest ao permitir que os testadores identifiquem contas de e-mail válidas em um servidor SMTP. Ao saber quais usuários existem, um atacante pode direcionar ataques de força bruta, phishing ou engenharia social de maneira mais eficaz. Identificar essas vulnerabilidades é o primeiro passo para mitigar riscos e fortalecer a segurança do servidor SMTP.

## 🖥️ Como Usar o Script <a name="como-usar-o-script"></a>

### Clonar o Repositório <a name="clonar-o-repositório"></a>

```bash
git clone https://github.com/CGabriel22/EnumScripts.git
cd EnumScripts/smtpEnum
```

### Executar o Script <a name="executar-o-script"></a>

Certifique-se de que você tenha o Python 3 instalado. Para rodar o script, utilize o seguinte comando:

```bash
python3 smtpenum.py <IP_DO_SERVIDOR_SMTP> <CAMINHO_PARA_USERLIST>
```

## 🌟 Futuras Melhorias <a name="futuras-melhorias"></a>

- Adicionar Suporte a TLS: Implementar a capacidade de conectar-se a servidores SMTP que utilizam criptografia TLS.
- Paralelização: Melhorar a eficiência do script utilizando threads para enviar múltiplos comandos VRFY simultaneamente.
- Relatórios Detalhados: Adicionar funcionalidades para gerar relatórios detalhados dos resultados.
- Customização de Comandos: Permitir a customização de comandos SMTP além do VRFY.
- Timeout de Conexão: Define um timeout de 10 segundos para a conexão do socket, evitando bloqueios indefinidos.
- Melhoria na Leitura e Envio de Dados: Verifica se a linha não está vazia antes de enviar a solicitação VRFY.

## 🚀 últimas Melhorias aplicadas <a name="futuras-melhorias"></a>

- Linguagem do script stualizada para Go, vizando um melhor desempenho
- Tratamento de Erros e Exceções: Capturar exceções específicas e gerais, fornecendo mensagens de erro claras.
- Validação de Entrada: Verificar se o arquivo da wordlist existe antes de tentar abri-lo.
- Fechamento Adequado do Socket: Agora, em GO, utilizo "defer conn.Close()" e "defer file.Close()" para garantir que a conexão e o arquivo serão devidamente fechados ao final da função main.


Este script auxilia no processo de pentest ao permitir que os testadores identifiquem contas de e-mail válidas em um servidor SMTP. Ao saber quais usuários existem, um atacante pode direcionar ataques de força bruta, phishing ou engenharia social de maneira mais eficaz. Identificar essas vulnerabilidades é o primeiro passo para mitigar riscos e fortalecer a segurança do servidor SMTP.

---

Este README fornece uma visão completa do propósito, funcionamento e importância do script de enumeração SMTP, assim como instruções detalhadas sobre como usá-lo e sugestões para futuras melhorias. Use este script com responsabilidade e sempre com a devida autorização.
