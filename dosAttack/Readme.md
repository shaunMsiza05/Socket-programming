# DoS / DDoS Lab — README

**Purpose**
Simple, local lab that demonstrates an application‑level connection‑exhaustion DoS (and an optional DDoS via many local bot workers). The server accepts a preconfigured number of concurrent sessions (`MAX_CONN`) and replies `BUSY` when capacity is reached. Bots open and hold connections to exhaust the slots so a legitimate client is rejected.

**Safety**
Run only on your own machine or isolated lab VM (127.0.0.1). Do **not** attack public systems.

---

## Files (place in one folder)

* `server.py` — capacity-limited server. Key settings: `MAX_CONN`, `HOLD_SECONDS`. Listens on `127.0.0.1:9000`.
* `attacker_dos.py` — simple attacker that opens `N` persistent connections and holds them.
* `bot_worker.py` — single bot worker used by the controller.
* `botnet_controller.py` — spawns many `bot_worker` processes to simulate many bots.
* `client.py` / `client_retry.py` — legitimate client; `client_retry.py` retries when server responds `BUSY`.

---

## Quick run (exact)

1. Start the server:

   ```bash
   python server.py
   ```

2. Exhaust slots with bots:

   * Single-process attacker:

     ```bash
     python attacker_dos.py
     ```

     (Ensure `N` in `attacker_dos.py` == `MAX_CONN` in `server.py`.)

   * Or spawn many bots via controller:

     ```bash
     python botnet_controller.py --num 6
     ```

     (Set `--num` ≥ `MAX_CONN`.)

3. While bots hold sockets, run the client:

   ```bash
   python client.py
   ```

   or observe `client_retry.py` printing repeated `BUSY` messages:

   ```bash
   python client_retry.py
   ```

4. Stop the bots (Ctrl‑C the attacker/controller) — client should then be served.

---

## Key configuration knobs

* `MAX_CONN` (in `server.py`) — number of concurrent sessions the server will accept. Default used in lab: **6**.
* `HOLD_SECONDS` (in `server.py`) — how long a served session holds its slot (increase to make DoS easier to observe).
* `N` (in `attacker_dos.py`) or `--num` (controller) — number of attacker sockets to open. Set ≥ `MAX_CONN`.
* `--hold` (bot_worker/controller) — how many seconds each bot holds a connection (0 = indefinite).

---

## What you will observe

* When bots occupy all `MAX_CONN` slots the server replies to new connections with:

  ```json
  {"type":"BUSY","msg":"Server at capacity, try again later"}
  ```
* Legitimate client receives `BUSY` until bots release sockets.
* Server logs show accepted connections for bots and released slots when bots stop.

---

## Quick troubleshooting

* Start order matters: **server → attacker/controller → client**.
* If client still gets served:

  * Confirm `MAX_CONN` matches bot count.
  * Ensure attacker shows connection replies (`opened slot #...`).
  * Increase `HOLD_SECONDS` so slots remain occupied long enough to test.
  * Use `netstat -tnp | grep 9000` (or OS equivalent) to confirm many established connections.

---

## Simple mitigations to demonstrate

* **Shorten `HOLD_SECONDS`** — reduces time slots are occupied.
* **Per-IP connection limits** — reject/limit multiple concurrent sessions from one IP.
* **Connection timeouts** / **idle time kill** — free stale sessions sooner.
* **Rate limiting & upstream filtering** — drop repeated connections at firewall/load‑balancer.
* **SYN cookies or TCP stack tuning** — mitigate SYN-flood style attacks (OS level).
* **Authentication + resource gating** — require cheap proof-of-work / captcha / client auth before allocating a heavy server slot.

---

## Exercises

1. Set `MAX_CONN=2` and `--num=2` to see BUSY quickly.
2. Add per-IP limit in `server.py` and show bot cannot hog all slots from one IP.
3. Modify server to evict oldest idle connection when a new trusted client appears (policy demo).
4. Use `botnet_controller.py --num 50` on multiple VMs or Docker containers (lab only) to simulate distributed sources.

---

## Quick checklist

* [ ] Files in same directory
* [ ] Python 3 installed
* [ ] Start server, then attacker/controller, then client
* [ ] Observe `BUSY` when slots exhausted
* [ ] Stop bots → client served
