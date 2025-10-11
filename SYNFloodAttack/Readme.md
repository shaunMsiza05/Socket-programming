# SYN‑Flood Simulation — README (safe lab)

**Purpose**
Safe, local simulation that reproduces the *symptom* of a SYN‑flood (listen/backlog exhaustion) without crafting raw SYN packets. Run on your own machine or an isolated VM to test detection and mitigation.

**Safety**
Only run on `127.0.0.1` or isolated lab hosts you own. Do **not** target public systems.

---

## Files included

* `syn_lab_server.py` — server with intentionally **small listen backlog**; accepts and holds connections briefly.
* `rapid_connecter.py` — many parallel connectors that rapidly open/close TCP connections to stress the server.
* `monitor_port9000.py` — cross-platform monitor that polls `netstat` and prints counts of states for port `9000`.
* (Optional) `botnet_controller.py` + `bot_worker.py` — alternate approach: many persistent bots to exhaust server slots (application‑level DoS).

---

## Quick run (exact steps)

1. Start the server:

   ```bash
   python syn_lab_server.py
   ```

   * Server logs `listening on 127.0.0.1:9000 (backlog=5)` by default.
   * You can edit `BACKLOG` and `WORKER_SLEEP` in the file to tune the test.

2. (Optional) Start the monitor in a second terminal:

   ```bash
   python monitor_port9000.py
   ```

   * Shows counts like `total=28 {'ESTABLISHED':10,'TIME_WAIT':15,'LISTEN':1}` every second.

3. Run the load generator in a third terminal:

   ```bash
   python rapid_connecter.py
   ```

   * Adjust `WORKERS`, `CONNS_PER_WORKER`, and `DELAY_BETWEEN` in the script to control intensity.

4. Observe:

   * Server terminal: many `accepted` lines until backlog saturates; may show `accept error` if overloaded.
   * Monitor terminal or `netstat`/PowerShell: spikes in `ESTABLISHED`, `TIME_WAIT` etc.
   * Rapid connector: many silent failures (expected) when backlog fills.

---

## What to expect

* With a very small backlog (e.g., 1–5) and high connection churn, new connections will be refused or time out.
* The symptom (backlog saturation) simulates the effect of a SYN flood without using raw packet forging.

---

## Configuration knobs (where to tweak)

* `syn_lab_server.py`

  * `BACKLOG`: TCP listen backlog size (small = easier to saturate)
  * `WORKER_SLEEP`: seconds each accepted connection holds the socket
* `rapid_connecter.py`

  * `WORKERS`: number of parallel threads
  * `CONNS_PER_WORKER`: number of connections each worker makes
  * `DELAY_BETWEEN`: delay between connects (seconds)
* `monitor_port9000.py`

  * `PORT`, `INTERVAL`: port to watch and polling interval

---

## Observing on non‑Linux (Windows / macOS)

* **Windows PowerShell**:

  ```powershell
  Get-NetTCPConnection -LocalPort 9000 | Group-Object -Property State | Format-Table
  Get-NetTCPConnection -LocalPort 9000 | Select-Object RemoteAddress,RemotePort,State
  ```
* **Windows GUI**: Resource Monitor → Network → TCP Connections.
* **TCPView (Sysinternals)**: live socket list.
* **macOS / generic**:

  ```bash
  netstat -an | grep "\.9000"
  ```
* Or run the included `monitor_port9000.py` (cross-platform).

---

## Simple mitigations to test

* Increase `BACKLOG` in the server; reduce `WORKER_SLEEP`.
* Add server-side accept throttling or per-IP connection limits (code change).
* On a Linux host (if available), toggle:

  ```bash
  sudo sysctl -w net.ipv4.tcp_syncookies=1
  sudo sysctl -w net.core.somaxconn=1024
  sudo sysctl -w net.ipv4.tcp_max_syn_backlog=4096
  ```

  (Only in lab; don’t change production systems without coordination.)

---

## Troubleshooting

* If the client still succeeds:

  * Ensure server started **before** the connector.
  * Verify `BACKLOG` is small and `WORKER_SLEEP` is long enough to hold slots.
  * Increase `WORKERS` / `CONNS_PER_WORKER` or decrease `DELAY_BETWEEN` to raise pressure.
* Use `monitor_port9000.py` or your OS `netstat`/PowerShell commands to confirm many sockets exist.

---

## Quick checklist before you test tomorrow

* [ ] Files present in same folder: `syn_lab_server.py`, `rapid_connecter.py`, `monitor_port9000.py`.
* [ ] Python 3 installed.
* [ ] Start order: server → monitor (optional) → rapid connector.
* [ ] Record observations: server logs, monitor output, connector success/fail counts.
