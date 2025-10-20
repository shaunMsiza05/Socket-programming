import socket
import threading

CLIENT_PORT = 5000
TUNNEL_IP = '127.0.0.1'   # Destination VTEP IP
TUNNEL_PORT = 6000        # Destination VTEP listening port

def handle_client(conn, addr):
    print(f"[VTEP_SRC] Client connected from {addr}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tunnel:
        tunnel.connect((TUNNEL_IP, TUNNEL_PORT))
        print(f"[VTEP_SRC] Tunnel established to Destination VTEP")

        while True:
            data = conn.recv(1024)
            if not data:
                break

            message = data.decode()
            print(f"[VTEP_SRC] Received from client: {message}")

            # Forward ARP request to Destination VTEP
            tunnel.send(message.encode())

            # Wait for reply
            reply = tunnel.recv(1024).decode()
            print(f"[VTEP_SRC] Got reply from Destination VTEP: {reply}")

            # Send reply back to client
            conn.send(reply.encode())

    conn.close()
    print("[VTEP_SRC] Connection closed.")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', CLIENT_PORT))
        s.listen(5)
        print(f"[VTEP_SRC] Listening for client connections on port {CLIENT_PORT}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
