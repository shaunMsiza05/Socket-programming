# client.py
import socket
import threading

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8000  # Load balancer port


def receive_messages(sock):
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                break
            print(f"\n[Chat] {data.decode().strip()}")
        except:
            break


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print(f"Connected to chat server via load balancer at {SERVER_HOST}:{SERVER_PORT}")

    threading.Thread(target=receive_messages, args=(client_socket,), daemon=True).start()

    while True:
        try:
            msg = input("> ")
            if msg.lower() == "exit":
                break
            client_socket.sendall(msg.encode())
        except:
            break

    client_socket.close()
    print("Disconnected from chat.")


if __name__ == "__main__":
    start_client()
