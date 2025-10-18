#!/usr/bin/env python3
"""
rapid_connecter.py
Safe lab script to rapidly create many TCP connections to 127.0.0.1:9000.

Usage: python rapid_connecter.py
Tweak WORKERS and CONNS_PER_WORKER to control intensity.
"""
import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 9000

WORKERS = 200           # number of concurrent threads
CONNS_PER_WORKER = 50   # number of connects per thread
DELAY_BETWEEN = 0.005   # delay between connects in each thread (seconds)

def worker(wid):
    for i in range(CONNS_PER_WORKER):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((HOST, PORT))
            # optionally send a small payload
            try:
                s.sendall(f"hello from worker {wid}\n".encode())
            except Exception:
                pass
            # close immediately to create churn
            s.close()
        except Exception:
            # expected: connection refused or timeout when backlog saturates
            pass
        time.sleep(DELAY_BETWEEN)
    print(f"[worker {wid}] done")

def main():
    threads = []
    t0 = time.time()
    for w in range(WORKERS):
        t = threading.Thread(target=worker, args=(w,), daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    print("rapid_connecter done in %.2fs" % (time.time() - t0))

if __name__ == "__main__":
    main()
