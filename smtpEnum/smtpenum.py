#!/usr/bin/python
import socket, sys

# verify if the number of arguments is correct
if len(sys.argv) != 3:
    print("Modo de uso: python3 smtpenum.py IP userlist")
    sys.exit(0)

# connect to SMTP Server
tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp.connect((sys.argv[1], 25))

# Receve and print the server banner
banner = tcp.recv(1024)
print(banner.decode())

# Open the wordlist file and verify the users
with open(sys.argv[2], 'r') as file:
    for line in file:
        user = line.strip()
        tcp.sendall(f"VRFY {user}\r\n".encode())
        response = tcp.recv(1024)
        print(response.decode())

# close connection
tcp.close()