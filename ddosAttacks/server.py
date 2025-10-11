#!/usr/bin/env python3
"""
server.py — capacity-limited demo server.
- Listens 127.0.0.1:9000 for client connections.
- Optional monitor on 127.0.0.1:9001 to forward copies of sent HEALTH_DATA.
- Accepts up to MAX_CONN concurrent sessions; excess connections receive BUSY and are closed.
"""
import socket, threading, json, time

HOST = "127.0.0.1"
CLIENT_PORT = 9000
MONITOR_PORT = 9001
MAX_CONN = 6
HOLD_SECONDS = 60   # how long each serviced connection holds its slot

slot_sem = threading.Semaphore(MAX_CONN)
monitor_lock = threading.Lock()
monitor_conn = None

def send_json(conn, obj):
    try:
        conn.sendall((json.dumps(obj) + "\n").encode())
    except:
        pass

def recv_json(conn, timeout=None):
    if timeout is not None:
        conn.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                return None
            buf += chunk
            if b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                return json.loads(line.decode())
    except Exception:
        return None

def handle_client(conn, addr):
    try:
        print(f"[server] servicing {addr} (slot acquired).")
        msg = recv_json(conn, timeout=5)
        if not msg:
            print(f"[server] no message from {addr}, closing.")
            return

        if msg.get("type") == "CONFIRM_IDENTITY" and msg.get("id"):
            payload = {
                "type":"HEALTH_DATA",
                "data":"Blood Pressure = 120/80; Heart Rate = 72",
                "timestamp": time.time()
            }
            send_json(conn, payload)
            print(f"[server] sent HEALTH_DATA to {addr}")

            # forward captured copy to monitor (optional)
            time.sleep(0.5)
            with monitor_lock:
                if monitor_conn:
                    try:
                        send_json(monitor_conn, {"type":"CAPTURED","copy":payload})
                        print("[server] forwarded copy to monitor")
                    except Exception as e:
                        print("[server] failed to forward to monitor:", e)

            # hold slot to simulate an active session (prevents new clients)
            time_start = time.time()
            while time.time() - time_start < HOLD_SECONDS:
                time.sleep(1)

        elif msg.get("type") == "REPLAY":
            print("[server] Received REPLAY from", addr)
            send_json(conn, {"type":"ACK","msg":"Replay accepted (demo)"})
        else:
            send_json(conn, {"type":"ERROR","msg":"Invalid request"})
    except Exception as e:
        print("[server] handler exception:", e)
    finally:
        try: conn.close()
        except: pass
        slot_sem.release()
        print(f"[server] connection closed {addr}; slot released")

def client_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, CLIENT_PORT))
    s.listen(200)
    print(f"[server] Listening on {HOST}:{CLIENT_PORT} (MAX_CONN={MAX_CONN})")
    while True:
        conn, addr = s.accept()
        acquired = slot_sem.acquire(blocking=False)
        if not acquired:
            send_json(conn, {"type":"BUSY","msg":"Server at capacity, try again later"})
            conn.close()
            print(f"[server] rejected {addr} (BUSY).")
            continue
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

def monitor_listener():
    global monitor_conn
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, MONITOR_PORT))
    s.listen(1)
    print(f"[server] Monitor port listening on {HOST}:{MONITOR_PORT}")
    while True:
        conn, addr = s.accept()
        with monitor_lock:
            if monitor_conn:
                try: monitor_conn.close()
                except: pass
            monitor_conn = conn
        print("[server] Monitor connected", addr)
        try:
            while True:
                data = conn.recv(4096)
                if not data: break
        except:
            pass
        finally:
            with monitor_lock:
                if monitor_conn is conn:
                    monitor_conn = None
            try: conn.close()
            except: pass
            print("[server] Monitor disconnected")

if __name__ == "__main__":
    threading.Thread(target=monitor_listener, daemon=True).start()
    client_listener()
