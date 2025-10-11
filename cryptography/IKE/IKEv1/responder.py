#!/usr/bin/env python3
"""
IKEv1 Responder (server) simulation supporting:
- Main mode (6-message)
- Aggressive mode (3-message)
- Quick mode (phase 2) following a completed Phase 1

This is purely for simulation/education. It uses UDP, JSON messages,
a simplified DH (modular exponentiation) and HMAC-SHA256 for authentication.
"""

import socket
import argparse
import json
import base64
import secrets
import hashlib
import hmac
import time

# Simple MODP parameters (smallish for speed in demo). Do NOT use in real crypto.
# For realistic sizes you'd grab real RFC primes. Here we use a 2048-bit
# if you want, but for demonstration we keep smaller for speed.
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563", 16)
DH_G = 2

MSG_TIMEOUT = 8.0

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
    # return a symmetric key derived from shared secret
    return sha256(str(shared).encode())

def send_msg(sock, addr, payload):
    sock.sendto(json.dumps(payload).encode(), addr)

def recv_msg(sock):
    data, addr = sock.recvfrom(8192)
    return json.loads(data.decode()), addr

class Responder:
    def __init__(self, host, port):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)
        self.sock.settimeout(None)
        print(f"[+] Responder listening on {host}:{port}")

        # store session state per initiator (keyed by ip:port)
        self.sessions = {}

    def run(self):
        while True:
            try:
                msg, addr = recv_msg(self.sock)
            except KeyboardInterrupt:
                print("Exiting")
                return
            except Exception as e:
                print("recv error:", e)
                continue

            key = f"{addr[0]}:{addr[1]}"
            print(f"\n[RECV] from {key}: {msg.get('type')}")
            handler = msg.get("type")
            if handler == "IKE_SA_INIT_MAIN_1" or handler == "IKE_SA_INIT_AGG_1":
                self.handle_phase1_init(msg, addr)
            elif handler.startswith("IKE_SA_MAIN_") or handler.startswith("IKE_SA_AGG_"):
                # Phase 1 follow-ups
                self.handle_phase1(msg, addr)
            elif handler.startswith("IKE_QUICK_"):
                self.handle_quick(msg, addr)
            else:
                print("[!] Unknown message type:", handler)

    def handle_phase1_init(self, msg, addr):
        mode = "main" if msg["type"] == "IKE_SA_INIT_MAIN_1" else "aggressive"
        initiator = f"{addr[0]}:{addr[1]}"
        print(f"[+] Phase1 {mode.upper()} start from {initiator}")

        # create session state
        session = {
            "mode": mode,
            "initiator": initiator,
            "peer_addr": addr,
            "state": 1
        }
        self.sessions[initiator] = session

        if mode == "main":
            # Send responder SA response (message 2)
            payload = {
                "type": "IKE_SA_MAIN_2",
                "sa": {"proposal": "responder-sa"},
            }
            send_msg(self.sock, addr, payload)
            print("[SENT] IKE_SA_MAIN_2 (SAr1)")
        else:
            # Aggressive mode: respond with SAr, KEr, Nr, IDr and auth
            priv_r, pub_r = dh_gen_keypair()
            session.update({"priv_r": priv_r, "pub_r": pub_r})
            # parse initiator values if present
            ke_i = int(msg.get("ke", "0"))
            ni = ub64(msg.get("nonce", "")) if msg.get("nonce") else b""
            session["ke_i"] = ke_i
            session["nonce_i"] = ni

            # generate own values
            nr = secrets.token_bytes(16)
            session["nonce_r"] = nr

            payload = {
                "type": "IKE_SA_AGG_2",
                "sa": {"proposal": "responder-sa"},
                "ke": str(pub_r),
                "nonce": b64(nr),
                "id": "responder@example",
            }
            # derive shared key (if ke_i present)
            if ke_i:
                sk = derive_shared_key(priv_r, ke_i)
                # compute auth over concatenated fields
                auth = hmac_sha256(sk, (str(payload["sa"]) + str(pub_r) + b64(nr)).encode())
                payload["auth"] = b64(auth)
                session["sk"] = sk
            send_msg(self.sock, addr, payload)
            session["state"] = 3
            print("[SENT] IKE_SA_AGG_2 (SAr, KEr, Nr, IDr, auth?)")

    def handle_phase1(self, msg, addr):
        initiator = f"{addr[0]}:{addr[1]}"
        session = self.sessions.get(initiator)
        if not session:
            print("[!] No session for", initiator)
            return
        mode = session["mode"]

        if mode == "main":
            # Expecting initiator KEi (message 3)
            if msg["type"] == "IKE_SA_MAIN_3":
                ke_i = int(msg.get("ke", "0"))
                ni = ub64(msg.get("nonce", "")) if msg.get("nonce") else b""
                session.update({"ke_i": ke_i, "nonce_i": ni})
                # generate responder KE, nonce
                priv_r, pub_r = dh_gen_keypair()
                session.update({"priv_r": priv_r, "pub_r": pub_r})
                nr = secrets.token_bytes(16)
                session["nonce_r"] = nr
                payload2 = {
                    "type": "IKE_SA_MAIN_4",
                    "ke": str(pub_r),
                    "nonce": b64(nr),
                }
                send_msg(self.sock, addr, payload2)
                session["state"] = 4
                print("[SENT] IKE_SA_MAIN_4 (KEr, Nr)")
            elif msg["type"] == "IKE_SA_MAIN_5":
                # Initiator sends IDi + auth
                # compute shared key and verify auth
                ke_i = session.get("ke_i")
                pub_r = session.get("pub_r")
                if not (ke_i and pub_r):
                    print("[!] Missing KE values")
                    return
                sk = derive_shared_key(session["priv_r"], ke_i)
                session["sk"] = sk
                authb64 = msg.get("auth", "")
                expected = hmac_sha256(sk, (msg.get("id", "") + "IDi").encode())
                if hmac.compare_digest(expected, ub64(authb64)):
                    # send IDr + auth
                    payload6 = {
                        "type": "IKE_SA_MAIN_6",
                        "id": "responder@example",
                    }
                    auth_r = hmac_sha256(sk, ("IDr" + payload6["id"]).encode())
                    payload6["auth"] = b64(auth_r)
                    send_msg(self.sock, addr, payload6)
                    session["state"] = 6
                    print("[SENT] IKE_SA_MAIN_6 (IDr, auth). Phase1 (Main) complete.")
                else:
                    print("[!] Auth verification failed (Main)")
        else:
            # Aggressive followups (message 3)
            if msg["type"] == "IKE_SA_AGG_3":
                # Initiator will send auth maybe - verify using sk if present
                # If we already derived sk earlier, verify
                ke_i = session.get("ke_i")
                priv_r = session.get("priv_r")
                if ke_i and priv_r:
                    sk = derive_shared_key(priv_r, ke_i)
                    session["sk"] = sk
                authb64 = msg.get("auth", "")
                if session.get("sk"):
