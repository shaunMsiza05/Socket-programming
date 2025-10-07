# load_balancer.py
import socket
import threading
from datetime import datetime

# --- Configuration ---
BACKEND_SERVERS = {
    "server1": ("127.0.0.1", 9001),
    "server2": ("127.0.0.1", 9002),
    "server3": ("127.0.0.1", 9003),
}

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8000

active_connections = {name: 0 for name in BACKEND_SERVERS}
lock = threading.Lock()


def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [LoadBalancer] {message}")


def get_least_connected_server():
    with lock:
        log(f"Active connections: {active_connections}")
        least_server = min(active_connections, key=active_connections.get)
        least_count = active_connections[least_server]
        log(f"Least connections found: {least_count} on {least_server}")
        log(f"Forwarding client to: {least_server}")
        return least_server


def forward(source, destination):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            destination.sendall(data)
    except:
        pass
    finally:
        source.close()
        destination.close()


def handle_client(client_socket, client_address):
    chosen_server = get_least_connected_server()
    server_ip, server_port = BACKEND_SERVERS[chosen_server]

    try:
        backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_socket.connect((server_ip, server_port))

        with lock:
            active_connections[chosen_server] += 1

        threading.Thread(target=forward, args=(client_socket, backend_socket)).start()
        threading.Thread(target=forward, args=(backend_socket, client_socket)).start()

    except Exception as e:
        log(f"Error forwarding client {client_address}: {e}")
        client_socket.close()
        with lock:
            if active_connections[chosen_server] > 0:
                active_connections[chosen_server] -= 1


def start_load_balancer():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((LISTEN_HOST, LISTEN_PORT))
    server.listen(100)
    log(f"Load balancer listening on {LISTEN_HOST}:{LISTEN_PORT}")

    while True:
        client_socket, addr = server.accept()
        log(f"New client from {addr}")
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()


if __name__ == "__main__":
    start_load_balancer()
