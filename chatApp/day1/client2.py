import socket
import threading

# IP address of the server (localhost for testing)
SERVER_IP = '127.0.0.1'
# Port number (must match server)
PORT = 12345

def receive_messages(sock):
    """
    Listens for incoming messages from the server and prints them.
    Runs in a background thread.
    """
    while True:
        try:
            # Receive message from server
            message = sock.recv(1024).decode()
            if not message:
                # Server closed the connection
                break
            # Print the message, refresh input line
            print("\r" + message + "\n> ", end="")
        except:
            # An error occurred (e.g. server down)
            print("[-] Connection lost.")
            break

def start_client():
    """
    Connects to the server and starts the chat loop.
    """
    # Create a TCP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Connect to the server
    client_socket.connect((SERVER_IP, PORT))

    print("[*] Connected to chat server.")
    print("Type your messages below (type /quit to exit):\n")

    # Start a background thread to receive messages
    thread = threading.Thread(target=receive_messages, args=(client_socket,))
    thread.daemon = True
    thread.start()

    while True:
        try:
            # Get user input
            message = input("> ")
            if message.lower() == "/quit":
                # Exit command
                break
            # Send the message to the server
            client_socket.sendall(message.encode())
        except KeyboardInterrupt:
            # Gracefully handle Ctrl+C
            break

    print("[-] Disconnecting...")
    # Close the socket
    client_socket.close()

# Entry point of the script
if __name__ == "__main__":
    start_client()
