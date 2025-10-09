#!/usr/bin/env python3
# server_two_clients_list.py

import socket

HOST = "0.0.0.0"
PORT = 12345

sock = socket.socket()
sock.bind((HOST, PORT))
sock.listen(2)
print(f"Server listening on {HOST}:{PORT}")

clients = []  # list of tuples (username, conn)

try:
    while len(clients) < 2:
        conn, addr = sock.accept()
        print(f"[+] Connection from {addr}")
        conn.sendall(b"Enter your username: ")
        username = conn.recv(1024).decode().strip()
        if not username:
            username = f"User{len(clients)+1}"
        clients.append((username, conn))
        print(f"[i] {username} has joined")

    print("[*] Two clients connected, starting chat session")
    (user1, c1), (user2, c2) = clients

    while True:
        # Client 1
        data = c1.recv(1024)
        if not data:
            print(f"[-] {user1} disconnected")
            break
        msg = data.decode().strip()
        if msg == "/list":
            user_list = ", ".join(u for u, _ in clients)
            c1.sendall(f"[Users online]: {user_list}".encode())
        else:
            c2.sendall(f"{user1}: {msg}".encode())

        # Client 2
        data = c2.recv(1024)
        if not data:
            print(f"[-] {user2} disconnected")
            break
        msg = data.decode().strip()
        if msg == "/list":
            user_list = ", ".join(u for u, _ in clients)
            c2.sendall(f"[Users online]: {user_list}".encode())
        else:
            c1.sendall(f"{user2}: {msg}".encode())

except KeyboardInterrupt:
    print("Server shutting down")
finally:
    for _, c in clients:
        c.close()
    sock.close()
