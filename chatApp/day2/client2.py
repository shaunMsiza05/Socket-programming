import socket
import threading

# IP address of the server (localhost for testing)
SERVER_IP = '192.168.146.146'
PORT = 12345


def receive_messages(sock):
    """
    Listens for incoming messages from the server and prints them.
    Runs in a background thread.
    """
    while True:
        try:
            message = sock.recv(1024).decode()
            if not message:
                break
            print("\r" + message + "\n> ", end="")
        except:
            print("[-] Connection lost.")
            break


def start_client():
    """
    Connects to the server and starts the chat loop.
    """
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, PORT))

    print("[*] Connected to chat server.")

    # --- NEW: prompt for username locally ---
    username = input("Choose a username: ")
    client_socket.sendall(username.encode())  # send it immediately to server

    print("Type your messages below (type /quit to exit):\n")

    # Start thread to receive messages
    thread = threading.Thread(target=receive_messages, args=(client_socket,), daemon=True)
    thread.start()

    while True:
        try:
            message = input("> ")
            if message.lower() == "/quit":
                client_socket.sendall("/quit".encode())
                break
            client_socket.sendall(message.encode())
        except KeyboardInterrupt:
            client_socket.sendall("/quit".encode())
            break

    print("[-] Disconnecting...")
    client_socket.close()


if __name__ == "__main__":
    start_client()
