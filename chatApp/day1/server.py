import socket
import threading

# Server will listen on all available network interfaces
HOST = '0.0.0.0'
# Port to bind the server socket to
PORT = 12345

# List to store all connected client sockets
clients = []

def broadcast(message, sender_socket):
    """
    Sends a message to all clients except the one who sent it.
    """
    for client in clients:
        if client != sender_socket:
            try:
                # Send the message to the client
                client.sendall(message)
            except:
                # If sending fails, close the socket and remove from list
                client.close()
                clients.remove(client)

def handle_client(client_socket, addr):
    """
    Handles communication with a single client.
    """
    print(f"[+] New connection from {addr}")
    # Add client to the list
    clients.append(client_socket)

    while True:
        try:
            # Receive message from client
            message = client_socket.recv(1024)
            if not message:
                # If message is empty, the client disconnected
                break
            # Broadcast the message to other clients
            broadcast(message, client_socket)
        except:
            # Error occurred, break the loop
            break

    # Client disconnected or errored out
    print(f"[-] Connection closed from {addr}")
    # Remove from list and close socket
    clients.remove(client_socket)
    client_socket.close()

def start_server():
    """
    Starts the TCP chat server.
    """
    # Create a socket using IPv4 and TCP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the host and port
    server_socket.bind((HOST, PORT))
    # Start listening for incoming connections
    server_socket.listen()
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        # Accept new client connection
        client_socket, addr = server_socket.accept()
        # Create a thread to handle the new client
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        # Set thread as daemon so it exits when main program exits
        thread.daemon = True
        # Start the thread
        thread.start()

# Entry point of the script
if __name__ == "__main__":
    start_server()
