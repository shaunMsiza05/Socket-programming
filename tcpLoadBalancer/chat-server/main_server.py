import socket
import threading

HOST = '0.0.0.0'
PORT = 5000
MAX_CLIENTS = 2

clients = []
lock = threading.Lock()

def broadcast(message, sender_socket):
    with lock:
        for client in clients:
            if client != sender_socket:
                try:
                    client.sendall(message)
                except:
                    client.close()
                    clients.remove(client)

def handle_client(client_socket, addr):
    with lock:
        if len(clients) >= MAX_CLIENTS:
            print(f"[REJECTED] {addr} - server full")
            client_socket.sendall(b"Server full. Try again later.\n")
            client_socket.close()
            return
        clients.append(client_socket)

    print(f"[CONNECTED] {addr}")

    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            message = f"[{addr[0]}:{addr[1]}] {data.decode()}".encode()
            broadcast(message, client_socket)
    except:
        pass
    finally:
        with lock:
            print(f"[DISCONNECTED] {addr}")
            clients.remove(client_socket)
            client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[SERVER] Listening on {HOST}:{PORT} (max {MAX_CLIENTS} clients)")

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
