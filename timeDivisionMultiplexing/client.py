import socket
import threading

HOST = "127.0.0.1"
PORT = 5000

def listen(sock):
    while True:
        data = sock.recv(1024)
        if not data:
            break
        print(data.decode().strip())

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    threading.Thread(target=listen, args=(sock,), daemon=True).start()

    while True:
        msg = input("")
        sock.sendall(msg.encode())

if __name__ == "__main__":
    main()
