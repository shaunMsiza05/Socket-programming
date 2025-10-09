import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 5000

# Step 1: Create server socket and wait for connection
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen(1)
    print(f"[Server] Waiting for client on {HOST}:{PORT}...")

    conn, addr = s.accept()
    with conn:
        print(f"[Server] Client connected from {addr}")

        # Step 2: Generate DH parameters (after client connects)
        print("[Server] Generating Diffie-Hellman parameters (512-bit prime)...")
        parameters = dh.generate_parameters(generator=2, key_size=512)
        pn = parameters.parameter_numbers()
        print(f"[Server] Prime (p): {pn.p}")
        print(f"[Server] Generator (g): {pn.g}")

        # Step 3: Generate server private and public keys
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        print("[Server] Server private key generated.")
        print("[Server] Server public key generated.")

        # Step 4: Send server public key
        server_public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("[Server] Sending public key to client...")
        conn.sendall(server_public_bytes)

        # Step 5: Receive client's public key
        client_public_bytes = conn.recv(2048)
        print("[Server] Received public key from client.")
        client_public_key = serialization.load_pem_public_key(client_public_bytes)

        # Step 6: Derive shared secret
        shared_key = private_key.exchange(client_public_key)
        print("[Server] Shared key derived successfully.")
        print(f"[Server] Shared secret (hex): {shared_key.hex()[:64]}...")
