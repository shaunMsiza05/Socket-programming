#!/usr/bin/env python3
"""
syn_lab_server.py
Safe lab server with intentionally small listen backlog to let you observe
what happens when many clients rapidly try to connect.

Run: python syn_lab_server.py
"""
import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 9000
BACKLOG = 5           # intentionally small for the lab
WORKER_SLEEP = 5      # how long a worker holds the connection (seconds)

def handle_conn(conn, addr):
    try:
        print(f"[server] accepted {addr}")
        # simple exchange: read one line (if any), then reply and hold
        conn.settimeout(2)
        try:
            data = conn.recv(1024)
            if data:
                print(f"[server] recv from {addr}: {data[:200]!r}")
        except Exception:
            pass
        try:
            conn.sendall(b"OK\n")
        except Exception:
            pass
        # hold connection for a bit to keep the accept queue engaged
        time.sleep(WORKER_SLEEP)
    except Exception as e:
        print("[server] handler error:", e)
    finally:
        try: conn.close()
        except: pass
        print(f"[server] closed {addr}")

def listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    # small backlog here — this is the lab variable you tweak
    s.listen(BACKLOG)
    print(f"[server] listening on {HOST}:{PORT} (backlog={BACKLOG})")
    while True:
        try:
            conn, addr = s.accept()
        except Exception as e:
            print("[server] accept error (likely backlog full or interrupt):", e)
            time.sleep(0.1)
            continue
        t = threading.Thread(target=handle_conn, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    listener()
