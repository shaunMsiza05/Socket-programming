# Testing Plan

## Environment
- Python 3.x
- Localhost server (`127.0.0.1:12345`)
- Tested on Linux/Windows/Mac

## Test Cases

### 1. Connectivity
- [ ] Client successfully connects to a running server.
- [ ] Invalid server IP/port results in connection failure.

### 2. Messaging
- [ ] Client can send messages to the server.
- [ ] Client receives messages broadcasted by the server.
- [ ] Multiple clients can exchange messages seamlessly.

### 3. Commands
- [ ] `/quit` disconnects the client gracefully.
- [ ] Ctrl+C closes the client without crashing.

### 4. Error Handling
- [ ] Server shutdown triggers "Connection lost" message.
- [ ] Invalid input does not break the client loop.

### 5. Performance
- [ ] Chat works with at least 10 simultaneous clients.
- [ ] Messages are delivered with minimal latency (<500 ms).
- [ ] System remains stable for 30+ minutes of continuous use.

## Notes
- Initial tests are done on localhost.
- Future tests should include cross-network scenarios (LAN/WAN).
