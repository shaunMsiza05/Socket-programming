import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1'
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print("[Client] Connecting to server...")
    s.connect((HOST, PORT))

    # Step 1: Receive server's public key
    server_public_bytes = s.recv(2048)
    print("[Client] Received server's public key.")
    server_public_key = serialization.load_pem_public_key(server_public_bytes)

    # Step 2: Extract DH parameters from server's key
    pn = server_public_key.public_numbers().parameter_numbers
    print(f"[Client] Extracted prime (p): {pn.p}")
    print(f"[Client] Extracted generator (g): {pn.g}")
    parameters = dh.DHParameterNumbers(pn.p, pn.g).parameters()

    # Step 3: Generate client keys
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    print("[Client] Client private key generated.")
    print("[Client] Client public key generated.")

    # Step 4: Send public key to server
    client_public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("[Client] Sending public key to server...")
    s.sendall(client_public_bytes)

    # Step 5: Derive shared key
    shared_key = private_key.exchange(server_public_key)
    print("[Client] Shared key derived successfully.")
    print(f"[Client] Shared secret (hex): {shared_key.hex()[:64]}...")
