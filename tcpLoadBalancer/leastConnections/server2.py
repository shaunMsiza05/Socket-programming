# chat_server.py
import socket
import threading
from datetime import datetime

HOST = "127.0.0.1"
PORT = 9002  # You can run multiple copies with different ports (9002, 9003, etc.)

clients = []  # List of client sockets
lock = threading.Lock()


def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [ChatServer:{PORT}] {message}")


def broadcast(message, sender_socket):
    with lock:
        for client in clients:
            if client != sender_socket:
                try:
                    client.sendall(message)
                except:
                    clients.remove(client)


def handle_client(client_socket, address):
    with lock:
        clients.append(client_socket)
    log(f"Client connected: {address}")

    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            log(f"Received from {address}: {data.decode().strip()}")
            broadcast(data, client_socket)
    except:
        pass
    finally:
        with lock:
            clients.remove(client_socket)
        client_socket.close()
        log(f"Client disconnected: {address}")


def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(10)
    log(f"Chat server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()


if __name__ == "__main__":
    start_server()
