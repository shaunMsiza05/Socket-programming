import socket
import threading

LISTEN_PORT = 6000
LOCAL_CLIENTS = []
ARP_TABLE = {}  # IP -> MAC mapping

def handle_vtep_src(conn, addr):
    print(f"[VTEP_DST] Tunnel connection from {addr}")

    while True:
        data = conn.recv(1024)
        if not data:
            break

        message = data.decode()
        parts = message.split("|")

        if parts[0] == "ARP_REQUEST":
            src_ip = parts[1]
            dst_ip = parts[2]

            print(f"\n[VTEP_DST] Received ARP request for {dst_ip}")

            if dst_ip in ARP_TABLE:
                # Suppression active — proxy reply
                mac = ARP_TABLE[dst_ip]
                reply = f"ARP_REPLY|{dst_ip}|{src_ip}|{mac}"
                print(f"[VTEP_DST] Found in ARP table. Replying with {mac}")
                conn.send(reply.encode())
            else:
                # No entry — broadcast to all local clients
                print(f"[VTEP_DST] No ARP entry. Broadcasting to local clients...")
                for c in LOCAL_CLIENTS:
                    c.send(message.encode())

                # Wait for client to respond
                response = None
                for c in LOCAL_CLIENTS:
                    try:
                        c.settimeout(5)
                        data = c.recv(1024)
                        if data:
                            response = data.decode()
                            break
                    except:
                        pass

                if response:
                    print(f"[VTEP_DST] Learned new ARP entry: {response}")
                    parts = response.split("|")
                    ip = parts[1]
                    mac = parts[3]
                    ARP_TABLE[ip] = mac
                    conn.send(response.encode())
                else:
                    print("[VTEP_DST] No response received from any local client.")

    conn.close()
    print("[VTEP_DST] Tunnel closed.")

def handle_local_client(conn, addr):
    print(f"[VTEP_DST] Local client connected from {addr}")
    LOCAL_CLIENTS.append(conn)

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', LISTEN_PORT))
        s.listen(5)
        print(f"[VTEP_DST] Listening for VTEP tunnel and clients on port {LISTEN_PORT}")

        while True:
            conn, addr = s.accept()

            # Identify whether this is from VTEP or local client (simple check)
            if addr[0] == '127.0.0.1':
                # Could be either; assume first connection is from vtep_src
                if len(LOCAL_CLIENTS) == 0:
                    threading.Thread(target=handle_vtep_src, args=(conn, addr), daemon=True).start()
                else:
                    threading.Thread(target=handle_local_client, args=(conn, addr), daemon=True).start()
            else:
                threading.Thread(target=handle_local_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
