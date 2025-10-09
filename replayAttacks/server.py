#!/usr/bin/env python3
"""
server.py - Replay-attack simulation server.

- Listens on 127.0.0.1:9000 for client connections (CONFIRM_IDENTITY).
- Listens on 127.0.0.1:9001 for a monitor/attacker connection (simulated capture).
- When a valid CONFIRM_IDENTITY is received, sends HEALTH_DATA to the client,
  then (after a short delay) sends a copy to the monitor connection as a simulated capture.
- If server later receives a REPLAY message on port 9000, it will log and ACK it
  (demonstrating a vulnerable server that doesn't check freshness/nonces).
"""

import socket
import threading
import json
import time

HOST = "127.0.0.1"
CLIENT_PORT = 9000
MONITOR_PORT = 9001

monitor_conn_lock = threading.Lock()
monitor_conn = None  # holds the monitor/attacker connection socket if connected

def send_json(conn, obj):
    data = json.dumps(obj) + "\n"
    conn.sendall(data.encode("utf-8"))

def recv_json(conn):
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, _, rest = buf.partition(b"\n")
            return json.loads(line.decode("utf-8"))

def handle_client(conn, addr):
    try:
        print(f"[server] client connected {addr}")
        msg = recv_json(conn)
        if not msg:
            print("[server] client closed connection without sending data")
            return

        if msg.get("type") == "CONFIRM_IDENTITY" and msg.get("id") == "client-123":
            print("[server] identity confirmed for", msg.get("id"))
            # Create confidential payload
            health = {
                "type": "HEALTH_DATA",
                "data": "Blood Pressure = 120/80; Heart Rate = 72",
                "timestamp": time.time()
            }
            # Send to client
            send_json(conn, health)
            print("[server] sent HEALTH_DATA to client:", health)

            # Simulate capture after a short delay (attacker captures later)
            time.sleep(0.5)
            with monitor_conn_lock:
                if monitor_conn:
                    try:
                        send_json(monitor_conn, {"type": "CAPTURED", "copy": health})
                        print("[server] sent CAPTURED copy to monitor (simulated sniff)")
                    except Exception as e:
                        print("[server] failed to forward to monitor:", e)
            # done for this client connection
        elif msg.get("type") == "REPLAY":
            # Simulate a server that accepts replayed packets (vulnerable)
            print("[server] Received REPLAY attempt from", addr)
            print("[server] REPLAY payload:", msg.get("replay_payload"))
            # For demo, server ACKs the replay as if it were valid
            send_json(conn, {"type": "ACK", "msg": "Replay processed (demo)"})
        else:
            send_json(conn, {"type": "ERROR", "msg": "Invalid request or missing confirmation"})
    except Exception as e:
        print("[server] exception in client handler:", e)
    finally:
        try:
            conn.close()
        except:
            pass
        print(f"[server] closed connection to {addr}")

def monitor_listener():
    global monitor_conn
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, MONITOR_PORT))
    s.listen(1)
    print(f"[server] Monitor (simulated attacker tap) listening on {HOST}:{MONITOR_PORT}")
    while True:
        conn, addr = s.accept()
        with monitor_conn_lock:
            if monitor_conn:
                try:
                    monitor_conn.close()
                except:
                    pass
            monitor_conn = conn
        print("[server] monitor connected from", addr)
        # Keep monitor connection open until it closes
        try:
            while True:
                # optionally read pings from monitor
                msg = recv_json(conn)
                if msg is None:
                    break
                if msg.get("type") == "PING":
                    send_json(conn, {"type": "PONG"})
        except Exception as e:
            print("[server] monitor connection error:", e)
        finally:
            with monitor_conn_lock:
                if monitor_conn is conn:
                    monitor_conn = None
            try:
                conn.close()
            except:
                pass
            print("[server] monitor disconnected")

def client_listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, CLIENT_PORT))
    s.listen(5)
    print(f"[server] Client API listening on {HOST}:{CLIENT_PORT}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    print("[server] starting...")
    threading.Thread(target=monitor_listener, daemon=True).start()
    client_listener()
