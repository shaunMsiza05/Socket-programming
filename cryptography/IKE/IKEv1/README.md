# 🧠 IKEv1 Simulation Using UDP Sockets

## 📘 Overview

This project simulates the **Internet Key Exchange Version 1 (IKEv1)** protocol using plain **UDP sockets in Python**.
It demonstrates the two main **Phase 1** modes of IKEv1 — **Main Mode** and **Aggressive Mode** — and the **Phase 2 Quick Mode** exchange used to establish IPsec Security Associations (SAs).

The goal is **educational**: to visualize how IKEv1 negotiates cryptographic parameters, performs Diffie–Hellman (DH) key exchange, and authenticates peers.
This is **not a secure implementation**, but a simplified model that helps understand protocol flow and logic.

---

## ⚙️ Features

✅ Implements **Main Mode (6 messages)** — the most common IKEv1 Phase 1 exchange
✅ Implements **Aggressive Mode (3 messages)** — faster but less secure
✅ Implements **Quick Mode (3 messages)** — Phase 2 key refresh/child SA establishment
✅ Uses **UDP sockets** to send and receive simulated IKE messages
✅ Performs a **simplified Diffie–Hellman key exchange**
✅ Uses **HMAC-SHA256** for simulated authentication
✅ Logs each message exchange clearly in both initiator and responder consoles
✅ Supports running both parties on localhost or across machines

---

## 🧩 Architecture

The project consists of two Python scripts:

| File                 | Role                   | Description                                                                           |
| -------------------- | ---------------------- | ------------------------------------------------------------------------------------- |
| `ikev1_responder.py` | **Responder (Server)** | Waits for incoming UDP packets and simulates the responder side of IKEv1              |
| `ikev1_initiator.py` | **Initiator (Client)** | Sends the first packet to start IKE negotiation and runs through the message sequence |

Each script maintains session state (nonces, DH keys, shared secrets, authentication material) in memory.

All packets are sent as **JSON**-encoded payloads over UDP, so you can easily inspect them or print them for learning purposes.

---

## 🧪 Protocol Simulation Flow

### Phase 1 — IKE SA Establishment

#### 🅰 Main Mode (6 messages)

| # | Sender                | Message              | Purpose                                    |
| - | --------------------- | -------------------- | ------------------------------------------ |
| 1 | Initiator → Responder | `IKE_SA_INIT_MAIN_1` | SA proposal from initiator                 |
| 2 | Responder → Initiator | `IKE_SA_MAIN_2`      | SA response from responder                 |
| 3 | Initiator → Responder | `IKE_SA_MAIN_3`      | Initiator sends KEi, Ni                    |
| 4 | Responder → Initiator | `IKE_SA_MAIN_4`      | Responder sends KEr, Nr                    |
| 5 | Initiator → Responder | `IKE_SA_MAIN_5`      | Initiator ID + Auth                        |
| 6 | Responder → Initiator | `IKE_SA_MAIN_6`      | Responder ID + Auth — **Phase 1 complete** |

#### 🅱 Aggressive Mode (3 messages)

| # | Sender                | Message             | Purpose                     |
| - | --------------------- | ------------------- | --------------------------- |
| 1 | Initiator → Responder | `IKE_SA_INIT_AGG_1` | SA, KEi, Ni, IDi            |
| 2 | Responder → Initiator | `IKE_SA_AGG_2`      | SAr, KEr, Nr, IDr, Auth     |
| 3 | Initiator → Responder | `IKE_SA_AGG_3`      | Auth — **Phase 1 complete** |

**Difference**: Aggressive Mode compresses messages to 3 instead of 6 but sends identity information before encryption, making it less secure.

---

### Phase 2 — Quick Mode (3 messages)

| # | Sender                | Message       | Purpose                                |
| - | --------------------- | ------------- | -------------------------------------- |
| 1 | Initiator → Responder | `IKE_QUICK_1` | Propose new SA, send Ni                |
| 2 | Responder → Initiator | `IKE_QUICK_2` | Accept SA, send Nr                     |
| 3 | Initiator → Responder | `IKE_QUICK_3` | Auth and finalize — **SA established** |

This simulates how IPsec Security Associations (SAs) are refreshed or negotiated using the **shared key derived in Phase 1**.

---

## 💻 How to Run

### 1️⃣ Start the Responder (Server)

```bash
python ikev1_responder.py --port 5000
```

It will listen for incoming IKE messages on UDP port `5000`.

---

### 2️⃣ Run the Initiator (Client)

#### Main Mode:

```bash
python ikev1_initiator.py --peer 127.0.0.1 --port 5000 --mode main
```

#### Aggressive Mode:

```bash
python ikev1_initiator.py --peer 127.0.0.1 --port 5000 --mode aggressive
```

#### Quick Mode (Phase 2):

```bash
python ikev1_initiator.py --peer 127.0.0.1 --port 5000 --mode quick
```

> 🧠 Run Quick Mode only **after** completing a successful Phase 1 — it depends on the derived session keys.

---

## 📜 Example Output

**Responder console:**

```
[+] Responder listening on 0.0.0.0:5000

[RECV] from 127.0.0.1:51638: IKE_SA_INIT_MAIN_1
[+] Phase1 MAIN start from 127.0.0.1:51638
[SENT] IKE_SA_MAIN_2 (SAr1)
[RECV] from 127.0.0.1:51638: IKE_SA_MAIN_3
[SENT] IKE_SA_MAIN_4 (KEr, Nr)
[RECV] from 127.0.0.1:51638: IKE_SA_MAIN_5
[SENT] IKE_SA_MAIN_6 (IDr, auth). Phase1 (Main) complete.
```

**Initiator console:**

```
[SENT] IKE_SA_INIT_MAIN_1
[RECV] IKE_SA_MAIN_2
[SENT] IKE_SA_MAIN_3
[RECV] IKE_SA_MAIN_4
[SENT] IKE_SA_MAIN_5
[RECV] IKE_SA_MAIN_6
[+] Phase1 Main completed successfully. SK established.
```

---

## 🔐 Cryptography Simplification

This simulation does not use full IKE cryptographic suites — instead, it mimics the operations with lightweight math:

| Concept                     | Simulated With                                 | Real Equivalent                    |
| --------------------------- | ---------------------------------------------- | ---------------------------------- |
| Diffie–Hellman key exchange | Simple modular exponentiation (`pow(g, a, p)`) | RFC-defined MODP groups            |
| Nonces                      | Random 16-byte tokens                          | Random bitstrings for freshness    |
| Authentication              | HMAC-SHA256                                    | RSA/PSK/DSS or certificates        |
| Encryption                  | None (plaintext JSON)                          | DES/3DES/AES for real IKE payloads |
| Message transport           | UDP JSON packets                               | Raw binary payloads over UDP/500   |

The goal is to **see how keys and messages flow**, not to provide encryption security.

---

## 🧠 Learning Objectives

This project helps you:

* Understand how **IKEv1 builds secure channels** before IPsec tunnels form
* Observe **DH key exchange** and nonce negotiation over UDP
* Compare **Main vs Aggressive mode** efficiency and privacy
* Learn how **Quick Mode** refreshes or rekeys the tunnel SA
* Gain confidence using Python sockets for secure protocol simulations

---

## 🧱 Folder Structure

```
ikev1-simulation/
├── ikev1_responder.py
├── ikev1_initiator.py
└── README.md
```

---

## 🔧 Possible Extensions

You can extend the simulation easily:

| Idea                             | Description                                     |
| -------------------------------- | ----------------------------------------------- |
| 🧩 Add retransmission logic      | Detect message loss and retry                   |
| 🔍 Add packet trace logging      | Save packet exchanges into `.pcap` or JSON logs |
| 🔐 Integrate real DH groups      | Use `cryptography` or `PyCryptodome`            |
| 📜 Add certificates              | Simulate RSA-signed AUTH payloads               |
| 🌐 Add NAT traversal             | Forward packets between translated IPs          |
| 🖥️ Add GUI or CLI visualization | Step through IKE messages interactively         |

---

## ⚠️ Disclaimer

> This project is for **educational and research purposes only**.
> It should **not** be used for real security or network encryption purposes.
> All cryptography here is simplified to illustrate IKEv1 message flow.

---

## 🧾 Author Notes

* Built entirely with Python’s `socket`, `json`, and `hashlib` libraries — no external dependencies.
* Works on any OS (Windows, Linux, macOS) that supports UDP sockets.
* Great for demonstrating VPN negotiation basics in labs or cybersecurity classes.

