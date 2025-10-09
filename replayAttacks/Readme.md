# Replay-Attack Lab — README

**Purpose:**
A minimal, ethical simulation demonstrating a TCP-based replay attack using three local programs: `server.py`, `client.py`, and `attacker.py`.

**Files**

* `server.py` — vulnerable service; listens on **127.0.0.1:9000** (client) and **127.0.0.1:9001** (monitor). Sends confidential `HEALTH_DATA` to client and forwards a copy to the monitor to simulate capture.
* `client.py` — legitimate client; sends `CONFIRM_IDENTITY` and receives `HEALTH_DATA`.
* `attacker.py` — connects to monitor port, prints/stores captured payload, and can replay it to the server.

**Requirements**

* Python 3
* Run locally in an isolated lab environment

**Quick run (three terminals)**

1. Start server: `python server.py`
2. Start attacker (monitor): `python attacker.py`
3. Start client: `python client.py`

**What to observe**

* Client receives and prints confidential data.
* Server forwards a copy to the monitor; attacker prints the compromised data immediately.
* Attacker may replay the captured payload; server (in this demo) accepts and ACKs the replay to demonstrate vulnerability.

**Mitigation ideas (next steps)**

* Add nonces + HMAC or a replay cache (server-side) to reject replays.
* Use TLS/mutual auth or signed requests.

**Ethics & safety**
This code is for learning in a controlled lab only. Do **not** intercept, capture, or replay traffic on systems you don’t own or have permission to test.

