#!/usr/bin/env python3
"""
client_retry.py — tries to connect until it receives HEALTH_DATA or exhausted retries.
"""
import socket, json, time

HOST = "127.0.0.1"
PORT = 9000
RETRIES = 20
WAIT = 2

def send_json(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode())

def recv_json(s, timeout=3.0):
    s.settimeout(timeout)
    buf = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                return None
            buf += chunk
            if b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                return json.loads(line.decode())
    except Exception:
        return None

for attempt in range(1, RETRIES+1):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((HOST, PORT))
        send_json(s, {"type":"CONFIRM_IDENTITY","id":"client-123"})
        resp = recv_json(s, timeout=3)
        if resp is None:
            print("[client] no response; connection closed")
            s.close()
            time.sleep(WAIT)
            continue
        if resp.get("type") == "BUSY":
            print(f"[client] server BUSY (attempt {attempt}/{RETRIES}): {resp.get('msg')}")
            s.close()
            time.sleep(WAIT)
            continue
        if resp.get("type") == "HEALTH_DATA":
            print("[client] got HEALTH_DATA:", resp.get("data"))
            s.close()
            break
        else:
            print("[client] unexpected response:", resp)
            s.close()
            break
    except Exception as e:
        print("[client] error:", e)
        time.sleep(WAIT)
else:
    print("[client] exhausted retries; giving up.")
