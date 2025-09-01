import socket
import threading

# Server will listen on all available network interfaces
HOST = '192.168.146.146'
PORT = 12345

# Dictionary to map client sockets -> usernames
clients = {}
lock = threading.Lock()  # Prevent race conditions when modifying clients


def broadcast(message, sender_socket=None):
    """
    Sends a message to all connected clients.
    If sender_socket is given, exclude that client.
    """
    with lock:
        for client in list(clients.keys()):
            if client != sender_socket:
                try:
                    client.sendall(message.encode())
                except:
                    # If sending fails, remove client
                    client.close()
                    del clients[client]


def handle_client(client_socket, addr):
    """
    Handles communication with a single client.
    """
    try:
        # First message from client must be username
        username = client_socket.recv(1024).decode().strip()
        if not username:
            username = f"User{addr[1]}"  # fallback username if empty

        with lock:
            clients[client_socket] = username

        # Notify others
        broadcast(f"*** {username} has joined the chat ***", client_socket)
        print(f"[+] {username} connected from {addr}")

        while True:
            message = client_socket.recv(1024).decode()
            if not message:
                break  # Disconnected

            if message.startswith("/"):  # handle commands
                if message.lower() == "/list":
                    # Send list of active users back only to requester
                    user_list = ", ".join(clients.values())
                    client_socket.sendall(f"[Server]: Online users: {user_list}\n".encode())
                elif message.lower() == "/quit":
                    break
                else:
                    client_socket.sendall("[Server]: Unknown command.\n".encode())
            else:
                # Broadcast chat message
                broadcast(f"[{username}]: {message}", client_socket)

    except Exception as e:
        print(f"[!] Error with {addr}: {e}")

    finally:
        # Remove client on disconnect
        with lock:
            if client_socket in clients:
                left_user = clients[client_socket]
                del clients[client_socket]
                broadcast(f"*** {left_user} has left the chat ***")
                print(f"[-] {left_user} disconnected")

        client_socket.close()


def start_server():
    """
    Starts the TCP chat server.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True)
        thread.start()


if __name__ == "__main__":
    start_server()
