import socket
import threading

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 4000

def receive_messages(sock):
    try:
        while True:
            msg = sock.recv(1024)
            if not msg:
                break
            print("\r" + msg.decode() + "\n> ", end="")
    except:
        pass
    finally:
        print("\n[DISCONNECTED FROM SERVER]")
        sock.close()

def start_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    print(f"[CONNECTED] to chat server at {SERVER_HOST}:{SERVER_PORT}")
    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    try:
        while True:
            msg = input("> ")
            if msg.lower() in ('exit', 'quit'):
                break
            sock.sendall(msg.encode())
    except KeyboardInterrupt:
        print("\n[EXIT]")
    finally:
        sock.close()

if __name__ == "__main__":
    start_client()
