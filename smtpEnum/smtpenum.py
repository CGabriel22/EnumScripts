#!/usr/bin/python
import socket, sys, re

# verify if the number of arguments is correct
if len(sys.argv) != 3:
    print("Modo de uso: python3 smtpenum.py IP userlist")
    sys.exit(0)

# connect to SMTP Server
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.connect((sys.argv[1], 25))

# Receve and print the server banner
banner = tcp.recv(1024)
print(banner.decode() + "\n")

# Open the wordlist file and verify the users
with open(sys.argv[2], 'r') as file:
    print("Buscando usuários...\n\n")
    for line in file:
        user = line.strip()
        tcp.sendall(f"VRFY {user}\r\n".encode())
        response = tcp.recv(1024)
        if re.search("252", response.decode()):
            user = response.decode().strip("252 2.0.0")
            print(f"Usuário encontrado: {user}")

# close connection
tcp.close()