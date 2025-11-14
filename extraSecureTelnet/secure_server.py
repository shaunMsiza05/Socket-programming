import socket
import threading
import base64
from Crypto.Cipher import AES
import os
import hashlib

# --- Layered Encryption Utilities ---

def pad(data):
    return data + b" " * (16 - len(data) % 16)

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def aes_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data).rstrip(b" ")

def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_decrypt(data, key):
    return xor_encrypt(data, key)  # symmetric

def base64_layer_encrypt(data):
    return base64.b64encode(data)

def base64_layer_decrypt(data):
    return base64.b64decode(data)

def reverse_encrypt(data):
    return data[::-1]

def reverse_decrypt(data):
    return data[::-1]

# --- Key Exchange (Diffie–Hellman style) ---

def generate_dh_keys():
    g = 5
    p = 23
    private = int.from_bytes(os.urandom(2), 'big')
    public = pow(g, private, p)
    return private, public, g, p

def compute_shared_key(their_public, private, p):
    return pow(their_public, private, p)

# --- 4-Layer Encryption Tunnel ---

def tunnel_encrypt(msg, key):
    layer1 = aes_encrypt(msg.encode(), key)
    layer2 = xor_encrypt(layer1, key)
    layer3 = base64_layer_encrypt(layer2)
    layer4 = reverse_encrypt(layer3)
    return layer4

def tunnel_decrypt(msg, key):
    layer1 = reverse_decrypt(msg)
    layer2 = base64_layer_decrypt(layer1)
    layer3 = xor_decrypt(layer2, key)
    layer4 = aes_decrypt(layer3, key)
    return layer4.decode()

# --- Server Functionality ---

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")

    # Key exchange
    private, public, g, p = generate_dh_keys()
    conn.send(f"{public},{g},{p}".encode())
    client_pub = int(conn.recv(1024).decode())
    shared_key = compute_shared_key(client_pub, private, p)
    aes_key = hashlib.sha256(str(shared_key).encode()).digest()[:16]

    print(f"[!] Shared key established with {addr}")

    while True:
        data = conn.recv(4096)
        if not data:
            break
        msg = tunnel_decrypt(data, aes_key)
        print(f"Client: {msg}")

        if msg.lower() == "exit":
            break

        reply = input("Server > ")
        encrypted_reply = tunnel_encrypt(reply, aes_key)
        conn.send(encrypted_reply)

    conn.close()
    print(f"[-] Disconnected {addr}")

def start_server():
    s = socket.socket()
    s.bind(("0.0.0.0", 9000))
    s.listen(5)
    print("[+] Secure Telnet Server listening on port 9000")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()
