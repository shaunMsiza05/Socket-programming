#!/usr/bin/env python3
"""
IKEv2 Responder simulation with CHILD_SA demonstration.

Usage:
    python ikev2_responder.py --port 5000

This listens on UDP and responds to IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA, and
decrypts child-SA-protected sample traffic using the derived child key.
"""

import socket, argparse, json, base64, secrets, hashlib, hmac, time
from typing import Tuple

# Optional cryptography for AES-GCM child-SA encryption demo
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

# Small demo MODP (not secure) — for speed in lab
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

def hmac_sha256(k: bytes, m: bytes) -> bytes:
    return hmac.new(k, m, hashlib.sha256).digest()

def dh_gen_pair() -> Tuple[int,int]:
    priv = secrets.randbelow(DH_P - 2) + 2
    pub = pow(DH_G, priv, DH_P)
    return priv, pub

def derive_ike_key(shared_secret: int, ni: bytes, nr: bytes) -> bytes:
    # Simplified key derivation: K = SHA256(shared_secret || Ni || Nr)
    return sha256(str(shared_secret).encode() + ni + nr)

def derive_child_key(ike_sk: bytes, label: bytes, ni: bytes, nr: bytes) -> bytes:
    # Child key = SHA256(ike_sk || label || Ni || Nr)
    return sha256(ike_sk + label + ni + nr)

def send(sock, addr, obj):
    sock.sendto(json.dumps(obj).encode(), addr)

def recv(sock, timeout=None):
    if timeout is not None:
        sock.settimeout(timeout)
    data, addr = sock.recvfrom(8192)
    return json.loads(data.decode()), addr

class Responder:
    def __init__(self, host, port):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        print(f"[+] Responder listening on {host}:{port}")
        self.sessions = {}  # key: peer ip:port

    def run(self):
        while True:
            try:
                msg, addr = recv(self.sock)
            except KeyboardInterrupt:
                print("Exiting")
                return
            except Exception as e:
                print("recv error:", e)
                continue
            peer = f"{addr[0]}:{addr[1]}"
            typ = msg.get("type")
            print(f"\n[RECV] {peer} -> {typ}")
            if typ == "IKE_SA_INIT":
                self.handle_init(msg, addr)
            elif typ == "IKE_AUTH":
                self.handle_auth(msg, addr)
            elif typ == "CREATE_CHILD_SA":
                self.handle_create_child(msg, addr)
            elif typ == "CHILD_TRAFFIC":
                self.handle_child_traffic(msg, addr)
            else:
                print("[!] Unknown message:", typ)

    def handle_init(self, msg, addr):
        peer = f"{addr[0]}:{addr[1]}"
        print("[*] IKE_SA_INIT received")
        # store initiator values
        ke_i = int(msg.get("ke", "0"))
        ni = ub64(msg.get("nonce")) if msg.get("nonce") else b""
        sa = msg.get("sa", {})
        # generate responder KE and nonce
        priv_r, pub_r = dh_gen_pair()
        nr = secrets.token_bytes(16)
        # compute shared secret if KEi present
        shared = None
        ike_sk = None
        if ke_i:
            shared = pow(ke_i, priv_r, DH_P)
            ike_sk = derive_ike_key(shared, ni, nr)
        # store session
        self.sessions[peer] = {
            "mode": "ikev2",
            "ke_i": ke_i,
            "ni": ni,
            "priv_r": priv_r,
            "pub_r": pub_r,
            "nr": nr,
            "ike_sk": ike_sk
        }
        resp = {"type": "IKE_SA_INIT_RESP", "sa": {"accepted": True}, "ke": str(pub_r), "nonce": b64(nr)}
        if ike_sk:
            resp["cookie"] = b64(sha256(ike_sk)[:8])  # simple cookie demo
        send(self.sock, addr, resp)
        print("[SENT] IKE_SA_INIT_RESP")

    def handle_auth(self, msg, addr):
        peer = f"{addr[0]}:{addr[1]}"
        s = self.sessions.get(peer)
        if not s:
            send(self.sock, addr, {"type": "IKE_ERROR", "reason": "no_ike_sa"})
            print("[!] AUTH but no session")
            return
        print("[*] IKE_AUTH received - verifying auth")
        # derive ike_sk if not done
        if not s.get("ike_sk"):
            ke_i = s.get("ke_i")
            if ke_i:
                shared = pow(ke_i, s["priv_r"], DH_P)
                s["ike_sk"] = derive_ike_key(shared, s["ni"], s["nr"])
        ike_sk = s["ike_sk"]
        # verify auth (simulated HMAC over id)
        auth_b64 = msg.get("auth", "")
        auth = ub64(auth_b64) if auth_b64 else b""
        expected = hmac_sha256(ike_sk, b"peer-auth")
        if hmac.compare_digest(auth, expected):
            print("[+] AUTH verified. IKE_SA established.")
            # responder sends AUTH back (simulated)
            resp_auth = hmac_sha256(ike_sk, b"responder-auth")
            send(self.sock, addr, {"type": "IKE_AUTH_RESP", "auth": b64(resp_auth)})
            s["established"] = True
        else:
            print("[!] AUTH failed")
            send(self.sock, addr, {"type": "IKE_ERROR", "reason": "auth_failed"})

    def handle_create_child(self, msg, addr):
        peer = f"{addr[0]}:{addr[1]}"
        s = self.sessions.get(peer)
        if not s or not s.get("established"):
            send(self.sock, addr, {"type": "IKE_ERROR", "reason": "no_ike_or_not_established"})
            return
        print("[*] CREATE_CHILD_SA received")
        # Accept and create child SA: derive child key
        label = b"child-sa-1"
        ike_sk = s["ike_sk"]
        child_key = derive_child_key(ike_sk, label, s["ni"], s["nr"])
        s["child_key"] = child_key
        s["child_established"] = True
        # reply with confirmation
        send(self.sock, {"peer": addr[0], "port": addr[1]}, {"type": "CREATE_CHILD_RESP", "child_ok": True, "label": "child-sa-1"})
        # Note: above send signature is wrong. Fix: send(socket, addr, obj)
        # (we can't call socket here because send() signature needs sock parameter)
        # Instead, use send defined earlier; patch below accordingly.
        # We'll implement correctly:
    def handle_create_child(self, msg, addr):
        peer = f"{addr[0]}:{addr[1]}"
        s = self.sessions.get(peer)
        if not s or not s.get("established"):
            send(self.sock, addr, {"type": "IKE_ERROR", "reason": "no_ike_or_not_established"})
            return
        print("[*] CREATE_CHILD_SA received")
        label = b"child-sa-1"
        ike_sk = s["ike_sk"]
        child_key = derive_child_key(ike_sk, label, s["ni"], s["nr"])
        s["child_key"] = child_key
        s["child_established"] = True
        send(self.sock, addr, {"type": "CREATE_CHILD_RESP", "child_ok": True, "label": "child-sa-1"})
        print("[SENT] CREATE_CHILD_RESP (child established)")

    def handle_child_traffic(self, msg, addr):
        peer = f"{addr[0]}:{addr[1]}"
        s = self.sessions.get(peer)
        if not s or not s.get("child_established"):
            send(self.sock, addr, {"type": "IKE_ERROR", "reason": "child_not_established"})
            return
        print("[*] CHILD_TRAFFIC received (encrypted payload)")
        ct_b64 = msg.get("payload", "")
        iv_b64 = msg.get("iv", "")
        ct = ub64(ct_b64)
        iv = ub64(iv_b64)
        key = s["child_key"]
        if HAVE_CRYPTO:
            try:
                aesgcm = AESGCM(key[:32])  # 256-bit key
                pt = aesgcm.decrypt(iv, ct, None)
                print("[+] Decrypted child-traffic payload:", pt.decode(errors="replace"))
                send(self.sock, addr, {"type": "CHILD_TRAFFIC_ACK", "status": "ok"})
            except Exception as e:
                print("[!] Decrypt failed:", e)
                send(self.sock, addr, {"type": "CHILD_TRAFFIC_ACK", "status": "decrypt_failed"})
        else:
            # fallback: simple XOR decode (for demo only)
            plain = bytes([ct[i] ^ key[i % len(key)] for i in range(len(ct))])
            print("[+] Decrypted (xor demo) child-traffic payload:", plain.decode(errors="replace"))
            send(self.sock, addr, {"type": "CHILD_TRAFFIC_ACK", "status": "ok"})

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args()
    r = Responder(args.host, args.port)
    r.run()
