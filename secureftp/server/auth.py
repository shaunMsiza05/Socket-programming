import json
import os
import base64
import nacl.signing
import nacl.exceptions

KEYS_FILE = "known_keys.json"

if os.path.exists(KEYS_FILE):
    with open(KEYS_FILE, "r") as f:
        known_keys = json.load(f)
else:
    known_keys = {}

def save_keys():
    with open(KEYS_FILE, "w") as f:
        json.dump(known_keys, f, indent=2)

def verify_signature(sender_id, public_key_b64, message: bytes, signature_b64: str):
    public_key_bytes = base64.b64decode(public_key_b64)
    signature_bytes = base64.b64decode(signature_b64)

    if sender_id in known_keys:
        stored_key = base64.b64decode(known_keys[sender_id])
        if stored_key != public_key_bytes:
            return False, "Public key mismatch for sender_id"
    else:
        known_keys[sender_id] = public_key_b64
        save_keys()

    try:
        verify_key = nacl.signing.VerifyKey(public_key_bytes)
        verify_key.verify(message, signature_bytes)
        return True, "Signature valid"
    except nacl.exceptions.BadSignatureError:
        return False, "Bad signature"
