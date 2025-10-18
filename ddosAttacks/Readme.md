# Replay & DoS/DDoS Lab — README

**Purpose**
A concise lab that demonstrates two vulnerabilities in a controlled local environment:

1. **Replay attack** — attacker captures a confidential packet (simulated) and replays it later to the server.
2. **Connection-exhaustion DoS / DDoS** — many clients (bots) exhaust the server's preconfigured connection slots so a legitimate client receives `BUSY`.

> **Safety:** Run locally (127.0.0.1) or in an isolated VM. Do **not** run against systems you do not own or have permission to test.

---

## Files (drop into one folder)

* `server.py` — capacity-limited server (listens on 127.0.0.1:9000; optional monitor on :9001). `MAX_CONN` controls how many concurrent sessions are served; excess connections get a `BUSY` response.
* `client.py` — legitimate client that sends `CONFIRM_IDENTITY` and expects `HEALTH_DATA`.
* `attacker.py` — simulated replay attacker that connects to monitor port, prints captured data, and can replay it to the server.
* `server_dos.py` / `server.py` — (same) server with configurable `HOLD_SECONDS` to simulate long sessions.
* `attacker_dos.py` — single-process DoS attacker that opens `N` sockets and holds them.
* `bot_worker.py` — a single bot worker (used by controller).
* `botnet_controller.py` — spawns many bot workers (simulates DDoS). Supports `--num`, `--hold`, and `--auto-launch-client`.
* `client_retry.py` — a simple client that retries until served or gives up.

---

## Quick run (recommended order)

1. Start the server:

   ```bash
   python server.py
   ```

2. (Replay lab) Start the attacker monitor in a terminal:

   ```bash
   python attacker.py
   ```

3. Start the legitimate client:

   ```bash
   python client.py
   ```

   * Observe: client receives `HEALTH_DATA`; attacker prints captured data; attacker can replay and server (demo) accepts it.

4. (DoS / DDoS lab) Start botnet controller to spawn bots and exhaust slots (set `--num` ≥ `MAX_CONN`):

   ```bash
   python botnet_controller.py --num 6
   ```

   Wait until controller reports bots connected.

5. Then run `client.py` (or `client_retry.py`) — it should receive `BUSY` while bots hold the slots.

---

## Key concepts demonstrated

* **Replay attack:** Without freshness checks (nonces/timestamps/HMAC), previously valid messages can be replayed successfully.
* **Connection-exhaustion DoS:** Application-level slots (MAX_CONN) can be exhausted by many simultaneous sessions; legitimate clients get rejected with `BUSY`.

---

## Mitigations to try (exercise suggestions)

* **Nonces + HMAC** or one-time tokens: bind each request to a server-issued nonce and verify HMAC — replays fail.
* **Replay cache / nonce tracking:** server stores used nonces or message IDs and rejects duplicates.
* **Shorter session timeouts & per-IP limits:** reduce `HOLD_SECONDS`, enforce per-IP concurrent limits to limit single-host exhaustion.
* **SYN cookies / infrastructure rate-limiting:** demonstrate TCP-level protections or use a load balancer/ACLs.
* **TLS + mutual auth / session tokens:** authenticate clients cryptographically so blind replay is harder.

---

## Parameters to tune

* `MAX_CONN` (server): number of concurrent sessions the server will serve.
* `HOLD_SECONDS` (server): how long a served session holds its slot (increase for easier DoS observation).
* Controller `--num` (bots): how many worker bots to spawn.
* Worker `--hold`: seconds each bot keeps the socket open (0 = indefinite).

---

## Short checklist

* [ ] Files in same directory
* [ ] Python 3 installed
* [ ] Start server first, then attacker/controller, then client
* [ ] Observe attacker captured output and client `BUSY` when appropriate

-