Here’s a complete, professional-style **README.md** you can include with your IKEv2 simulation project — written to clearly explain the purpose, flow, and structure of your simulation.

---

# 🔐 IKEv2 Simulation using UDP Sockets

### Overview

This project is a **Python-based simulation** of the **Internet Key Exchange version 2 (IKEv2)** protocol — the key management protocol used by IPsec VPNs.

It demonstrates the **main message exchanges** defined in [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296):

1. **IKE_SA_INIT** – performs Diffie–Hellman key exchange and nonce exchange.
2. **IKE_AUTH** – authenticates peers and establishes the IKE Security Association (IKE SA).
3. **CREATE_CHILD_SA** – creates one or more Child SAs that actually protect data traffic (the most distinctive feature of IKEv2).

After these phases, the simulation **exhibits the Child SA** by encrypting and decrypting a sample “IP packet” payload to show how protected traffic flows once the negotiation is complete.

---

## 🧠 Learning Goals

This simulation aims to provide a hands-on understanding of:

* The **message flow** and **states** of IKEv2.
* How **Diffie–Hellman** key exchange is used to derive shared secrets.
* How **nonces** and **labels** contribute to key derivation.
* The role of the **Child SA** in separating traffic protection from IKE control.
* Basic **encryption/decryption** demonstration of an IPsec-protected payload.

---

## ⚙️ Features

* Implemented entirely using **Python UDP sockets** (no external VPN tools required).
* Simulates:

  * IKE_SA_INIT (exchange of DH public values and nonces)
  * IKE_AUTH (authentication using HMAC over a shared key)
  * CREATE_CHILD_SA (child SA negotiation)
  * Encrypted sample “IP packet” exchange via AES-GCM or XOR fallback
* Lightweight, readable, and designed for experimentation and study.

---

## 📂 File Structure

| File                 | Description                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------ |
| `ikev2_initiator.py` | The IKEv2 Initiator (client). Starts negotiation, authenticates, and creates Child SAs.    |
| `ikev2_responder.py` | The IKEv2 Responder (server). Accepts proposals, verifies authentication, and manages SAs. |
| `README.md`          | This documentation explaining setup, operation, and background.                            |

---

## 🧩 Protocol Flow (Simulated)

| Exchange            | Direction             | Description                                                   |
| ------------------- | --------------------- | ------------------------------------------------------------- |
| `IKE_SA_INIT`       | Initiator → Responder | Sends SA proposal, DH public value (KEi), and nonce (Ni).     |
| `IKE_SA_INIT_RESP`  | Responder → Initiator | Responds with KE_r and nonce (Nr). Shared secret is computed. |
| `IKE_AUTH`          | Initiator → Responder | Sends identity and HMAC-based authentication.                 |
| `IKE_AUTH_RESP`     | Responder → Initiator | Verifies and responds with its own authentication.            |
| `CREATE_CHILD_SA`   | Initiator → Responder | Requests a new Child SA for IPsec traffic.                    |
| `CREATE_CHILD_RESP` | Responder → Initiator | Confirms creation of the Child SA.                            |
| `CHILD_TRAFFIC`     | Initiator → Responder | Sends a sample encrypted payload protected by the Child SA.   |
| `CHILD_TRAFFIC_ACK` | Responder → Initiator | Acknowledges successful decryption of the payload.            |

---

## 🔑 Cryptographic Operations (Simplified)

| Purpose                     | Algorithm Used                         | Notes                                      |    |   |      |                      |
| --------------------------- | -------------------------------------- | ------------------------------------------ | -- | - | ---- | -------------------- |
| Diffie–Hellman key exchange | MODP group (toy parameters)            | Not secure — small prime for demonstration |    |   |      |                      |
| Key derivation              | `SHA-256(shared_secret                 |                                            | Ni |   | Nr)` | Simplified IKEv2 PRF |
| Authentication              | `HMAC-SHA256` over static string       | Simulated IKE_AUTH                         |    |   |      |                      |
| Child SA encryption         | AES-GCM (if available) or XOR fallback | Demonstrates packet protection             |    |   |      |                      |

---

## 🧪 Running the Simulation

### Prerequisites

Python 3.8+
Optionally install `cryptography` for real AES-GCM encryption:

```bash
pip install cryptography
```

### 1️⃣ Start the Responder (Server)

```bash
python ikev2_responder.py --port 5000
```

### 2️⃣ Start the Initiator (Client)

```bash
python ikev2_initiator.py --peer 127.0.0.1 --port 5000
```

### 3️⃣ Observe the Exchange

You should see the following progression in your terminals:

**Initiator:**

```
[*] IKE_SA_INIT complete. Derived IKE SK.
[*] IKE_AUTH verified. IKE_SA established.
[*] Requesting CREATE_CHILD_SA
[*] Child SA established. Child key derived.
[*] Sending sample traffic protected by Child SA
[RECV] CHILD_TRAFFIC_ACK ok
```

**Responder:**

```
[*] IKE_SA_INIT received
[SENT] IKE_SA_INIT_RESP
[*] IKE_AUTH received - verifying auth
[+] AUTH verified. IKE_SA established.
[*] CREATE_CHILD_SA received
[SENT] CREATE_CHILD_RESP (child established)
[*] CHILD_TRAFFIC received (encrypted payload)
[+] Decrypted child-traffic payload: Hello from initiator - this is protected by Child SA
```

This output confirms that both peers derived matching keys and successfully used the Child SA to protect traffic.

---

## 🔍 Understanding the Child SA Demonstration

In IKEv2, the **IKE SA** protects IKE control messages, while **Child SAs** protect user traffic (ESP, AH).

This simulation explicitly **shows the difference**:

* The initial IKE SA handles negotiation and authentication.
* The **Child SA** key is separately derived using:

  ```
  child_key = SHA256(IKE_SK || label || Ni || Nr)
  ```
* The initiator encrypts a test payload with the `child_key` and sends it.
* The responder decrypts it successfully — proving the child SA is functioning.

This mirrors how real IPsec tunnels protect user traffic after IKE negotiation.

---

## 🧠 Educational Extensions

You can extend this simulation further by:

* Implementing **HKDF** for stronger key derivation.
* Adding **SPIs** (Security Parameter Indexes) to identify SAs.
* Supporting **multiple Child SAs** (each with distinct keys).
* Simulating **rekeying** via another `CREATE_CHILD_SA` exchange.
* Exporting messages to a JSON “packet log” for visualization.

---

## ⚠️ Disclaimer

This project is **for educational purposes only**.
It uses insecure, simplified cryptographic operations and should **not** be used to secure real communication.
Its purpose is to **illustrate IKEv2’s logic and flow**, not to replace an IPsec implementation.

---

## 🧾 Summary

| Concept                          | Demonstrated?       |
| -------------------------------- | ------------------- |
| IKE_SA_INIT / IKE_AUTH           | ✅                   |
| CREATE_CHILD_SA                  | ✅                   |
| Child SA key derivation          | ✅                   |
| Encrypted traffic using Child SA | ✅                   |
| Rekeying / Delete SA             | ❌ (can be added)    |
| Real cryptographic security      | ❌ (simulation only) |

-