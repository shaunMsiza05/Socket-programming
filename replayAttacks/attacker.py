#!/usr/bin/env python3
"""
attacker.py - Simulated attacker that:
  1) Connects to the server's monitor port (127.0.0.1:9001) to receive a CAPTURED copy.
  2) Immediately prints the compromised/confidential information to its terminal.
  3) Stores the captured payload.
  4) Optionally replays the captured payload to the server (127.0.0.1:9000) on user prompt.
"""

import socket
import json
import time
import sys

HOST = "127.0.0.1"
MONITOR_PORT = 9001
CLIENT_PORT = 9000

def send_json(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))

def recv_json(conn):
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
        if b"\n" in buf:
            line, _, rest = buf.partition(b"\n")
            try:
                return json.loads(line.decode("utf-8"))
            except Exception:
                # bad JSON
                return None

def pretty_print_captured(captured):
    """Nicely display captured confidential information."""
    print("\n" + "="*60)
    print("[attacker] *** COMPROMISED DATA CAPTURED ***")
    try:
        t = captured.get("timestamp")
        if t:
            print("[attacker] captured timestamp:", time.ctime(float(t)))
    except Exception:
        pass
    # Print full captured object
    print("[attacker] payload:")
    print(json.dumps(captured, indent=2))
    print("="*60 + "\n")

def listen_for_capture(timeout=60):
    """Connect to monitor port and wait for a CAPTURED message."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((HOST, MONITOR_PORT))
        print(f"[attacker] connected to monitor port {HOST}:{MONITOR_PORT}")
    except Exception as e:
        print(f"[attacker] failed to connect to monitor: {e}")
        return None
    try:
        msg = recv_json(s)
        if msg is None:
            print("[attacker] monitor connection closed without data")
            return None
        if msg.get("type") == "CAPTURED":
            captured = msg.get("copy")
            print("[attacker] received CAPTURED copy from monitor")
            # Immediately display the compromised information
            pretty_print_captured(captured)
            return captured
        else:
            print("[attacker] unexpected monitor message:", msg)
            return None
    finally:
        try:
            s.close()
        except:
            pass

def replay_payload(payload):
    """Open a fresh connection to the server and send a REPLAY message."""
    print("[attacker] connecting to server to replay payload...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((HOST, CLIENT_PORT))
        print("[attacker] connected to server on client port", (HOST, CLIENT_PORT))
        # Show what we're about to replay
        print("[attacker] REPLAYING payload (shown below):")
        pretty_print_captured(payload)
        send_json(s, {"type": "REPLAY", "replay_payload": payload})
        # read server response
        resp = recv_json(s)
        print("[attacker] server response to REPLAY:", resp)
    except Exception as e:
        print("[attacker] error sending replay:", e)
    finally:
        try:
            s.close()
        except:
            pass

def main():
    print("[attacker] Waiting for captured packet on monitor port...")
    captured = listen_for_capture(timeout=120)
    if not captured:
        print("[attacker] nothing captured; exiting")
        sys.exit(1)

    # Offer user options: replay now, save to disk, or exit
    while True:
        print("Options: [r]eplay now  [s]ave to file  [q]uit")
        choice = input("Choice: ").strip().lower()
        if choice == "r":
            replay_payload(captured)
        elif choice == "s":
            fname = f"captured_{int(time.time())}.json"
            with open(fname, "w") as f:
                json.dump(captured, f, indent=2)
            print(f"[attacker] saved captured payload to {fname}")
        elif choice == "q":
            print("[attacker] exiting.")
            break
        else:
            print("Unknown option; choose r, s or q.")

if __name__ == "__main__":
    main()
