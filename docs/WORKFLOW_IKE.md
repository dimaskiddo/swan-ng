# SWAN-NG — IKE Core Concepts

IKE is the control plane for IPsec. SWAN-NG handles it in user-space on UDP 500 (standard) and UDP 4500 (NAT-T).

---

## Common Workflow

Before encrypted data flows, IKE establishes cryptographic keys. Both v1 and v2 follow this high-level pattern:

```mermaid
sequenceDiagram
    participant Initiator as VPN Client (Initiator)
    participant Responder as SWAN-NG (Responder)

    note over Initiator, Responder: Phase 1 (IKE SA) - Secure Control Channel
    Initiator->>Responder: Propose Crypto Suites (AES, SHA, DH Group)
    Responder-->>Initiator: Accept & Match Suite
    Initiator->>Responder: Diffie-Hellman (DH) Key Exchange
    Responder-->>Initiator: Diffie-Hellman (DH) Key Exchange
    note over Initiator, Responder: Shared Secret Established (SKEYSEED)

    note over Initiator, Responder: Phase 2 (Child SA / IPsec SA) - Data Channel
    Initiator->>Responder: Request IPsec SA (SPIs, Encryption Keys)
    Responder-->>Initiator: Accept IPsec SA (SPIs, Encryption Keys)
    note over Initiator, Responder: ESP Data Plane is now active
```

---

## Security Association (SA)

Logical contract between peers defining encryption/decryption rules.

| SA Type | Purpose |
|---|---|
| **IKE SA** | Encrypts IKE control messages (keep-alives, rekeying requests) |
| **Child SA (IPsec SA)** | Encrypts actual user traffic via ESP data plane |

Each SA identified by a **Security Parameter Index (SPI)** — 32-bit (IPsec) or 64-bit (IKE) number in the packet header.

## Security Policy Database (SPD)

Firewall rule-set dictating which traffic must be encrypted.

| Traffic | Action |
|---|---|
| Matches protected CIDR (e.g., `10.0.0.0/24`) | Encrypt and send via ESP |
| No match | Bypass / drop (unencrypted) |

---

## IKE Header

Every IKE packet (v1 and v2) begins with this 28-byte header:

```mermaid
packet-beta
title IKE Packet Header (RFC 7296)
0-63: "Initiator SPI (64 bits)"
64-127: "Responder SPI (64 bits)"
128-135: "Next Payload"
136-139: "Major Ver"
140-143: "Minor Ver"
144-151: "Exchange Type"
152-159: "Flags (Init, Resp, Msg)"
160-191: "Message ID"
192-223: "Length (Total Packet)"
```

- **Initiator/Responder SPI** — looks up cryptographic keys in `SessionManager`.
- **Major Version** — routes to `internal/ikev1` or `internal/ikev2` engine.
- **Message ID** — detects packet loss and replay attacks over UDP.
