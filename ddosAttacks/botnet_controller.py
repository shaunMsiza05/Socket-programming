#!/usr/bin/env python3
"""
botnet_controller.py — spawn multiple bot_worker.py processes to simulate a botnet.
Usage: python botnet_controller.py --num 50
"""
import subprocess, sys, time, argparse, threading, queue, os

def start_worker(python, script, idx, host, port, hold):
    args = [python, script, "--host", host, "--port", str(port), "--id", f"bot-{idx}", "--hold", str(hold)]
    return subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

def monitor_process(proc, idx, q):
    for line in proc.stdout:
        if line:
            q.put((idx, line.strip()))
    proc.wait()
    q.put((idx, f"__EXIT__:{proc.returncode}"))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--num", type=int, default=10)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--hold", type=int, default=0)
    p.add_argument("--python", default=sys.executable)
    p.add_argument("--script", default="bot_worker.py")
    p.add_argument("--auto-launch-client", action="store_true")
    args = p.parse_args()

    N = args.num
    procs = []
    q = queue.Queue()

    for i in range(N):
        proc = start_worker(args.python, args.script, i, args.host, args.port, args.hold)
        t = threading.Thread(target=monitor_process, args=(proc, i, q), daemon=True)
        t.start()
        procs.append((proc, t))
        time.sleep(0.02)

    connected = set()
    start_time = time.time()
    timeout = 15
    print(f"[controller] spawned {N} bots. Waiting for connection replies (timeout {timeout}s)...")

    while True:
        try:
            idx, line = q.get(timeout=timeout)
        except queue.Empty:
            break
        print(f"[worker {idx}] {line}")
        if "__EXIT__" in line:
            pass
        else:
            # crude: mark connection replies as connected when we see 'connected reply' or 'connected' in line
            if "connected reply" in line.lower() or "connected" in line.lower() or "conn" in line.lower():
                connected.add(idx)
        if len(connected) >= N:
            break
        if time.time() - start_time > timeout:
            break

    print(f"[controller] connected bots: {len(connected)}/{N}")
    if len(connected) >= N:
        print("[controller] ALL BOTS CONNECTED. Server slots should now be exhausted.")
    else:
        print("[controller] Not all bots reported connected; check server/worker logs.")

    if args.auto_launch_client:
        try:
            subprocess.Popen([args.python, "client.py"])
            print("[controller] launched client.py")
        except Exception as e:
            print("[controller] failed to launch client:", e)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[controller] terminating bots...")
        for proc, _ in procs:
            try: proc.terminate()
            except: pass
        print("[controller] exit.")

if __name__ == "__main__":
    main()
