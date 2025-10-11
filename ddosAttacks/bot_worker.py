#!/usr/bin/env python3
"""
bot_worker.py — single bot worker. Connects, sends CONFIRM_IDENTITY, holds socket.
"""
import socket, json, time, argparse

def send_json(s, obj):
    s.sendall((json.dumps(obj) + "\n").encode())

def recv_json(s, timeout=2.0):
    s.settimeout(timeout)
    try:
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: return None
            buf += chunk
            if b"\n" in buf:
                line, _, _ = buf.partition(b"\n")
                return json.loads(line.decode())
    except Exception:
        return None

def run(host, port, id_tag, hold_seconds):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        send_json(s, {"type":"CONFIRM_IDENTITY","id": id_tag})
        resp = recv_json(s, timeout=2.0)
        print(f"[bot:{id_tag}] connected reply: {resp}")
        start = time.time()
        while hold_seconds == 0 or (time.time() - start) < hold_seconds:
            time.sleep(1)
    except Exception as e:
        print(f"[bot:{id_tag}] error: {e}")
    finally:
        try: s.close()
        except: pass
        print(f"[bot:{id_tag}] exiting")

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--id", default="bot")
    p.add_argument("--hold", type=int, default=0, help="seconds to hold (0=indefinite)")
    args = p.parse_args()
    run(args.host, args.port, args.id, args.hold)
