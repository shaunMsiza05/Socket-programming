# System Design

## Overview
The system is a lightweight client-server chat application designed for local or small-scale testing. The architecture uses Python sockets for TCP communication and threading for concurrency.

## Architecture

### Client
- Creates a TCP socket connection to the server.
- Spawns two threads:
  - **Main thread**: Reads user input and sends messages.
  - **Receiver thread**: Listens for incoming messages and displays them.

### Server (planned)
- Listens for client connections on a defined port.
- Spawns a handler (thread or async process) per client.
- Broadcasts received messages to all connected clients.

## Data Flow
1. Client initiates a TCP connection to the server.
2. User input is encoded and sent to the server.
3. The server relays the message to all connected clients.
4. Clients receive and decode the message in a background thread.
5. Messages are displayed in real time.

## Planned Enhancements
- Support for nicknames or usernames.
- Private messages (`/msg user`).
- Command system (`/list`, `/help`, etc.).
- Logging and message history.
- TLS encryption for secure communications.
