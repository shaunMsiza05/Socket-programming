#!/usr/bin/env python3
"""
client.py — simple legitimate client that requests HEALTH_DATA once.
"""
import socket, json, time

HOST = "127.0.0.1"
PORT = 9000

def send_json(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode())

def recv_json(s, timeout=5):
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

if __name__ == "__main__":
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))
        print("[client] connected to server")
        send_json(s, {"type":"CONFIRM_IDENTITY","id":"client-123"})
        resp = recv_json(s, timeout=5)
        if not resp:
            print("[client] no response (connection closed)")
        elif resp.get("type") == "BUSY":
            print("[client] server BUSY:", resp.get("msg"))
        elif resp.get("type") == "HEALTH_DATA":
            print("[client] got HEALTH_DATA:", resp.get("data"))
            print("[client] timestamp:", resp.get("timestamp"))
        else:
            print("[client] unexpected:", resp)
    except Exception as e:
        print("[client] error:", e)
    finally:
        try: s.close()
        except: pass
