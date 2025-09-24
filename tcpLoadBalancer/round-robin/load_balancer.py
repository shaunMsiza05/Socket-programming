import socket
import threading

BACKEND_SERVERS = [
    ("127.0.0.1", 5000),
    ("127.0.0.1", 5001),
]

BALANCER_HOST = "0.0.0.0"
BALANCER_PORT = 4000

server_index = 0
index_lock = threading.Lock()

def get_next_server():
    global server_index
    with index_lock:
        server = BACKEND_SERVERS[server_index]
        server_index = (server_index + 1) % len(BACKEND_SERVERS)
    return server

def forward(src, dst):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
    except:
        pass
    finally:
        src.close()
        dst.close()

def handle_client(client_socket):
    backend_host, backend_port = get_next_server()
    try:
        backend_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend_socket.connect((backend_host, backend_port))
        print(f"[FORWARDING] Client -> {backend_host}:{backend_port}")
    except Exception as e:
        print(f"[ERROR] Could not connect to backend {backend_host}:{backend_port} - {e}")
        client_socket.sendall(b"Backend server unavailable.\n")
        client_socket.close()
        return

    threading.Thread(target=forward, args=(client_socket, backend_socket), daemon=True).start()
    threading.Thread(target=forward, args=(backend_socket, client_socket), daemon=True).start()

def start_balancer():
    balancer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    balancer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    balancer.bind((BALANCER_HOST, BALANCER_PORT))
    balancer.listen(100)
    print(f"[LOAD BALANCER] Listening on {BALANCER_HOST}:{BALANCER_PORT}")

    while True:
        client_socket, addr = balancer.accept()
        print(f"[NEW CONNECTION] From {addr}")
        threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()

if __name__ == "__main__":
    start_balancer()
