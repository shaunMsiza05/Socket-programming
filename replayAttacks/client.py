#!/usr/bin/env python3
"""
client.py - Legitimate client.

- Connects to server at 127.0.0.1:9000
- Sends CONFIRM_IDENTITY {"type":"CONFIRM_IDENTITY","id":"client-123"}
- Receives HEALTH_DATA and prints it, then closes.
"""

import socket
import json
import time

HOST = "127.0.0.1"
CLIENT_PORT = 9000

def send_json(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode("utf-8"))

def recv_json(s):
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, _, rest = buf.partition(b"\n")
            return json.loads(line.decode("utf-8"))

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, CLIENT_PORT))
    print("[client] connected to server")
    # Send confirmation
    send_json(s, {"type": "CONFIRM_IDENTITY", "id": "client-123"})
    print("[client] CONFIRM_IDENTITY sent")
    # Receive response (HEALTH_DATA)
    resp = recv_json(s)
    if resp:
        if resp.get("type") == "HEALTH_DATA":
            print("[client] received HEALTH_DATA:", resp.get("data"))
            print("[client] timestamp:", resp.get("timestamp"))
        else:
            print("[client] received unexpected response:", resp)
    else:
        print("[client] no response or connection closed")
    s.close()
    print("[client] done.")

if __name__ == "__main__":
    main()
