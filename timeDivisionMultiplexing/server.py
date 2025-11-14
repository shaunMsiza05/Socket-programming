import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 5000

SLOT_DURATION = 3       # seconds per slot
clients = []            # list of (conn, addr, id)
current_slot_index = 0
lock = threading.Lock()
running = True

def handle_client(conn, addr, client_id):
    global current_slot_index

    try:
        conn.sendall(f"CONNECTED. You are CLIENT {client_id}\n".encode())

        while running:
            data = conn.recv(1024)
            if not data:
                break

            message = data.decode().strip()

            with lock:
                active_client_id = clients[current_slot_index][2]

            # Check if client is allowed to send now
            if client_id != active_client_id:
                conn.sendall(b"ERROR: Not your time slot.\n")
                continue

            # Accept and broadcast valid message
            print(f"CLIENT {client_id}: {message}")

            broadcast(f"[Slot {client_id}] {message}")
    except:
        pass
    finally:
        conn.close()
        with lock:
            for i, c in enumerate(clients):
                if c[0] == conn:
                    del clients[i]
                    break
        print(f"Client {client_id} disconnected.")


def broadcast(msg: str):
    for conn, addr, cid in clients:
        try:
            conn.sendall((msg + "\n").encode())
        except:
            pass


def slot_scheduler():
    global current_slot_index

    while running:
        if len(clients) > 0:
            with lock:
                active_id = clients[current_slot_index][2]

            broadcast(f"--- TIME SLOT: CLIENT {active_id} ---")

            time.sleep(SLOT_DURATION)

            with lock:
                current_slot_index = (current_slot_index + 1) % len(clients)
        else:
            time.sleep(1)


def start_server():
    global running

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"TDM SERVER RUNNING ON {HOST}:{PORT}")

    threading.Thread(target=slot_scheduler, daemon=True).start()

    client_counter = 0

    try:
        while True:
            conn, addr = server.accept()
            client_id = client_counter
            client_counter += 1

            with lock:
                clients.append((conn, addr, client_id))

            print(f"Client {client_id} connected from {addr}")

            threading.Thread(
                target=handle_client,
                args=(conn, addr, client_id),
                daemon=True,
            ).start()

    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        running = False
        server.close()


if __name__ == "__main__":
    start_server()
