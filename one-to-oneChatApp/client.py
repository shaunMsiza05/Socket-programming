#!/usr/bin/env python3
# client_two_clients_list.py

import socket
import threading

HOST = "127.0.0.1"
PORT = 12345

def recv_loop(sock):
    while True:
        data = sock.recv(1024)
        if not data:
            break
        print("\n" + data.decode())

sock = socket.socket()
sock.connect((HOST, PORT))

# receive username prompt
prompt = sock.recv(1024).decode()
username = input(prompt)
sock.sendall(username.encode())

# start thread to receive messages
threading.Thread(target=recv_loop, args=(sock,), daemon=True).start()

# send messages
try:
    while True:
        msg = input()
        sock.sendall(msg.encode())
except KeyboardInterrupt:
    sock.close()
