#!/usr/bin/env python3
"""
IKEv2 Initiator simulation with CREATE_CHILD_SA + child traffic demonstration.

Usage:
    python ikev2_initiator.py --peer 127.0.0.1 --port 5000

This does:
 - IKE_SA_INIT
 - IKE_AUTH
 - CREATE_CHILD_SA
 - Encrypts a sample payload with the derived Child SA key and sends as CHILD_TRAFFIC
"""

import socket, argparse, json, base64, secrets, hashlib, hmac, time
from typing import Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

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
    return sha256(str(shared_secret).encode() + ni + nr)

def derive_child_key(ike_sk: bytes, label: bytes, ni: bytes, nr: bytes) -> bytes:
    return sha256(ike_sk + label + ni + nr)

def send(sock, addr, obj):
    sock.sendto(json.dumps(obj).encode(), addr)
    print("[SENT]", obj.get("type"))

def recv(sock, timeout=8.0):
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(8192)
        return json.loads(data.decode()), addr
    except socket.timeout:
        return None, None

class Initiator:
    def __init__(self, peer, port):
        self.peer = (peer, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.session = {}

    def run(self):
        # 1) IKE_SA_INIT
        priv_i, pub_i = dh_gen_pair()
        ni = secrets.token_bytes(16)
        self.session.update({"priv_i": priv_i, "pub_i": pub_i, "ni": ni})
        payload = {"type": "IKE_SA_INIT", "sa": {"proposal": "ikev2-demo"}, "ke": str(pub_i), "nonce": b64(ni)}
        send(self.sock, self.peer, payload)
        resp, _ = recv(self.sock)
        if not resp:
            print("[!] No response to IKE_SA_INIT")
            return
        print("[RECV]", resp.get("type"))
        ke_r = int(resp.get("ke", "0"))
        nr = ub64(resp.get("nonce", "")) if resp.get("nonce") else b""
        self.session.update({"ke_r": ke_r, "nr": nr})
        shared = pow(ke_r, priv_i, DH_P)
        ike_sk = derive_ike_key(shared, ni, nr)
        self.session["ike_sk"] = ike_sk
        print("[*] IKE_SA_INIT complete. Derived IKE SK.")

        # 2) IKE_AUTH
        auth = hmac_sha256(ike_sk, b"peer-auth")  # initiator proves knowledge
        payload2 = {"type": "IKE_AUTH", "id": "initiator@example", "auth": b64(auth)}
        send(self.sock, self.peer, payload2)
        resp2, _ = recv(self.sock)
        if not resp2:
            print("[!] No response to IKE_AUTH")
            return
        print("[RECV]", resp2.get("type"))
        # verify responder auth
        auth_r_b64 = resp2.get("auth", "")
        if hmac.compare_digest(ub64(auth_r_b64), hmac_sha256(ike_sk, b"responder-auth")):
            print("[+] IKE_AUTH verified. IKE_SA established.")
        else:
            print("[!] IKE_AUTH verification failed.")
            return

        # 3) CREATE_CHILD_SA
        print("[*] Requesting CREATE_CHILD_SA")
        send(self.sock, self.peer, {"type": "CREATE_CHILD_SA", "proposal": {"esp": "aes-gcm-256"}})
        resp3, _ = recv(self.sock)
        if not resp3:
            print("[!] No response to CREATE_CHILD_SA")
            return
        print("[RECV]", resp3.get("type"))
        if not resp3.get("child_ok"):
            print("[!] Child SA rejected")
            return
        label = resp3.get("label", "child-sa-1")
        child_key = derive_child_key(ike_sk, label.encode(), ni, nr)
        self.session["child_key"] = child_key
        print("[*] Child SA established. Child key derived.")

        # 4) Demonstrate child SA by encrypting a sample payload and sending CHILD_TRAFFIC
        sample = b"Hello from initiator - this is protected by Child SA"
        if HAVE_CRYPTO:
            aesgcm = AESGCM(child_key[:32])
            iv = secrets.token_bytes(12)
            ct = aesgcm.encrypt(iv, sample, None)
            send(self.sock, self.peer, {"type": "CHILD_TRAFFIC", "payload": b64(ct), "iv": b64(iv)})
            ack, _ = recv(self.sock)
            if ack:
                print("[RECV]", ack.get("type"), ack.get("status"))
        else:
            # fallback XOR
            ct = bytes([sample[i] ^ child_key[i % len(child_key)] for i in range(len(sample))])
            send(self.sock, self.peer, {"type": "CHILD_TRAFFIC", "payload": b64(ct), "iv": b64(b"")})
            ack, _ = recv(self.sock)
            if ack:
                print("[RECV]", ack.get("type"), ack.get("status"))

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--peer", required=True)
    p.add_argument("--port", type=int, default=5000)
    args = p.parse_args()
    cli = Initiator(args.peer, args.port)
    cli.run()
