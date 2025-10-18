# pop3_server.py
import socket
import threading

HOST = '127.0.0.1'
PORT = 1100

# Dummy mailbox data
USERS = {
    "shaun": "1234"
}

MAILBOX = {
    "shaun": [
        "From: alice@example.com\r\nSubject: Hello!\r\n\r\nHey Shaun, testing POP3 server.\r\n",
        "From: bob@example.com\r\nSubject: Reminder\r\n\r\nDon't forget the meeting.\r\n"
    ]
}

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    conn.sendall(b"+OK POP3 server ready\r\n")

    user = None
    authed = False

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            cmd = data.decode().strip()
            print(f"[{addr}] C: {cmd}")

            parts = cmd.split()
            if not parts:
                conn.sendall(b"-ERR Invalid command\r\n")
                continue

            command = parts[0].upper()

            if command == "USER":
                if len(parts) < 2:
                    conn.sendall(b"-ERR Missing username\r\n")
                    continue
                user = parts[1]
                conn.sendall(b"+OK User accepted\r\n")

            elif command == "PASS":
                if not user:
                    conn.sendall(b"-ERR USER required first\r\n")
                    continue
                if USERS.get(user) == parts[1]:
                    authed = True
                    conn.sendall(b"+OK Authenticated\r\n")
                else:
                    conn.sendall(b"-ERR Invalid credentials\r\n")

            elif command == "STAT" and authed:
                msgs = MAILBOX.get(user, [])
                total_size = sum(len(m) for m in msgs)
                conn.sendall(f"+OK {len(msgs)} {total_size}\r\n".encode())

            elif command == "LIST" and authed:
                msgs = MAILBOX.get(user, [])
                conn.sendall(f"+OK {len(msgs)} messages\r\n".encode())
                for i, m in enumerate(msgs, 1):
                    conn.sendall(f"{i} {len(m)}\r\n".encode())
                conn.sendall(b".\r\n")

            elif command == "RETR" and authed:
                if len(parts) < 2:
                    conn.sendall(b"-ERR Missing message number\r\n")
                    continue
                idx = int(parts[1]) - 1
                msgs = MAILBOX.get(user, [])
                if 0 <= idx < len(msgs):
                    msg = msgs[idx]
                    conn.sendall(f"+OK {len(msg)} octets\r\n".encode())
                    conn.sendall(msg.encode())
                    conn.sendall(b".\r\n")
                else:
                    conn.sendall(b"-ERR No such message\r\n")

            elif command == "QUIT":
                conn.sendall(b"+OK Goodbye\r\n")
                break

            else:
                conn.sendall(b"-ERR Unknown or unauthorized command\r\n")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        conn.close()
        print(f"[-] Connection closed for {addr}")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"POP3 server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
