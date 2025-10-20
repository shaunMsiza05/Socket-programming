import socket

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 6000

MY_IP = "10.1.1.20"
MY_MAC = "00:11:22:33:44:55"

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))
        print(f"[CLIENT_DST] Connected to Destination VTEP at {SERVER_HOST}:{SERVER_PORT}")

        while True:
            data = s.recv(1024)
            if not data:
                break
            message = data.decode()
            parts = message.split("|")

            if parts[0] == "ARP_REQUEST" and parts[2] == MY_IP:
                src_ip = parts[1]
                print(f"[CLIENT_DST] Got ARP request for me ({MY_IP}). Sending reply.")
                reply = f"ARP_REPLY|{MY_IP}|{src_ip}|{MY_MAC}"
                s.send(reply.encode())

if __name__ == "__main__":
    main()
