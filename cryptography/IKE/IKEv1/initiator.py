#!/usr/bin/env python3
"""
IKEv1 Initiator (client) simulation supporting:
- main / aggressive Phase1,
- quick mode (Phase2) after a Phase1 completes.

Usage examples:
python ikev1_initiator.py --peer 127.0.0.1 --port 5000 --mode main
python ikev1_initiator.py --peer 127.0.0.1 --port 5000 --mode aggressive
Then run quick: python ikev1_initiator.py --peer 127.0.0.1 --port 5000 --mode quick
"""

import socket
import argparse
import time
import json
import base64
import secrets
import hashlib
import hmac

DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
DH_G = 2

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()

def dh_gen_keypair():
    priv = secrets.randbelow(DH_P - 2) + 1
    pub = pow(DH_G, priv, DH_P)
    return priv, pub

def derive_shared_key(own_priv: int, peer_pub: int) -> bytes:
    shared = pow(peer_pub, own_priv, DH_P)
    return sha256(str(shared).encode())

def send(sock, addr, payload):
    sock.sendto(json.dumps(payload).encode(), addr)
    print("[SENT]", payload["type"])

def recv(sock, timeout=8.0):
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(8192)
        return json.loads(data.decode()), addr
    except socket.timeout:
        return None, None

class Initiator:
    def __init__(self, peer, port, mode):
        self.peer = (peer, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.mode = mode
        self.state = 0
        self.session = {}

    def run(self):
        if self.mode in ("main", "aggressive"):
            self.phase1()
        elif self.mode == "quick":
            self.quick_mode()
        else:
            print("Unknown mode")

    def phase1(self):
        if self.mode == "main":
            # send IKE_SA_INIT_MAIN_1 (SAi1)
            payload1 = {"type": "IKE_SA_INIT_MAIN_1", "sa": {"proposal": "init-sa"}}
            send(self.sock, self.peer, payload1)
            resp, addr = recv(self.sock)
            if not resp:
                print("[!] No reply for MAIN_2")
                return
            print("[RECV]", resp["type"])
            # expect SAr1
            # proceed with KEi
            priv_i, pub_i = dh_gen_keypair()
            self.session.update({"priv_i": priv_i, "pub_i": pub_i})
            ni = secrets.token_bytes(16)
            self.session["nonce_i"] = ni
            payload3 = {"type": "IKE_SA_MAIN_3", "ke": str(pub_i), "nonce": b64(ni)}
            send(self.sock, self.peer, payload3)
            # wait for KEr, Nr
            resp, addr = recv(self.sock)
            if not resp:
                print("[!] No reply for MAIN_4")
                return
            print("[RECV]", resp["type"])
            ke_r = int(resp.get("ke", "0"))
            nr = ub64(resp.get("nonce", "")) if resp.get("nonce") else b""
            self.session.update({"ke_r": ke_r, "nonce_r": nr})
            # compute shared key
            sk = derive_shared_key(self.session["priv_i"], ke_r)
            self.session["sk"] = sk
            # send IDi + auth (msg5)
            auth = hmac_sha256(sk, ("initiator-id" + "IDi").encode())
            payload5 = {"type": "IKE_SA_MAIN_5", "id": "initiator@example", "auth": b64(auth)}
            send(self.sock, self.peer, payload5)
            resp, addr = recv(self.sock)
            if not resp:
                print("[!] No reply for MAIN_6")
                return
            print("[RECV]", resp["type"])
            if resp.get("type") == "IKE_SA_MAIN_6":
                # verify responder auth
                auth_r = ub64(resp.get("auth", ""))
                expected = hmac_sha256(sk, ("IDr" + resp.get("id", "")).encode())
                if hmac.compare_digest(expected, auth_r):
                    print("[+] Phase1 Main completed successfully. SK established.")
                else:
                    print("[!] Responder auth verification failed.")
        else:
            # Aggressive mode
            priv_i, pub_i = dh_gen_keypair()
            self.session.update({"priv_i": priv_i, "pub_i": pub_i})
            ni = secrets.token_bytes(16)
            self.session["nonce_i"] = ni
            payload1 = {
                "type": "IKE_SA_INIT_AGG_1",
                "sa": {"proposal": "init-sa"},
                "ke": str(pub_i),
                "nonce": b64(ni),
                "id": "initiator@example"
            }
            send(self.sock, self.peer, payload1)
            resp, addr = recv(self.sock)
            if not resp:
                print("[!] No reply for AGG_2")
                return
            print("[RECV]", resp["type"])
            ke_r = int(resp.get("ke", "0"))
            nr = ub64(resp.get("nonce", "")) if resp.get("nonce") else b""
            self.session.update({"ke_r": ke_r, "nonce_r": nr})
            # derive sk and send auth (msg3)
            sk = derive_shared_key(self.session["priv_i"], ke_r)
            self.session["sk"] = sk
            auth = hmac_sha256(sk, b"agg-init")
            payload3 = {"type": "IKE_SA_AGG_3", "auth": b64(auth)}
            send(self.sock, self.peer, payload3)
            resp, addr = recv(self.sock)
            if resp:
                print("[RECV]", resp.get("type"))
                if resp.get("type") == "IKE_SA_AGG_DONE":
                    print("[+] Aggressive Phase1 complete. SK established.")
                else:
                    print("[!] Unexpected response:", resp)
            else:
                print("[!] No follow-up from responder after AGG_3")

    def quick_mode(self):
        # Quick mode requires a previously established SK (we simulate by doing a quick
        # ephemeral DH using a stored sk or deriving one via a small DH here).
        # For demo: perform a tiny handshake to derive a phase1-like sk locally,
        # then do quick exchange.
        # In practice you'd re-use the Phase1 SK and cookies.
        # Here we attempt to run Quick Mode directly and let Responder reject if no Phase1.
        ni = secrets.token_bytes(16)
        payload1 = {"type": "IKE_QUICK_1", "sa": {"proposal": "esp-3des"}, "nonce": b64(ni)}
        send(self.sock, self.peer, payload1)
        resp, addr = recv(self.sock)
        if not resp:
            print("[!] No reply to QUICK_1")
            return
        print("[RECV]", resp["type"])
        if resp.get("type") == "IKE_QUICK_2":
            nr = ub64(resp.get("nonce", "")) if resp.get("nonce") else b""
            # simulate deriving quick key from a non-existing phase1 key (responder should accept only if phase1 done)
            # Here, for demonstration, derive quick_key from concatenation of nonces (no real SK)
            quick_key = sha256(ni + nr)
            auth = hmac_sha256(quick_key, b"quick-init")
            payload3 = {"type": "IKE_QUICK_3", "auth": b64(auth)}
            send(self.sock, self.peer, payload3)
            resp2, addr = recv(self.sock)
            if resp2:
                print("[RECV]", resp2["type"])
                if resp2["type"] == "IKE_QUICK_DONE":
                    print("[+] Quick Mode (Phase 2) completed. SA active.")
                else:
                    print("[!] Quick Mode failure or rejection:", resp2)
            else:
                print("[!] No reply to QUICK_3")
        else:
            print("[!] Quick rejected:", resp)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--peer", required=True, help="Responder IP")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--mode", choices=["main", "aggressive", "quick"], default="main")
    args = p.parse_args()

    cli = Initiator(args.peer, args.port, args.mode)
    cli.run()
