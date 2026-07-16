# SWAN-NG — IKEv1

IKEv1 (RFC 2409) for backward compatibility with legacy endpoints and appliances.

---

## Main Mode (Phase 1)

6 messages establish the secure control channel (ISAKMP SA):

```mermaid
sequenceDiagram
    participant Initiator as IKEv1 Client
    participant Responder as SWAN-NG (IKEv1 Engine)

    note over Initiator, Responder: Main Mode (Phase 1)

    Initiator->>Responder: Message 1 (HDR, SA) <br> Proposes Security Associations
    Responder-->>Initiator: Message 2 (HDR, SA) <br> Accepts SA

    Initiator->>Responder: Message 3 (HDR, KE, Ni) <br> Key Exchange & Nonce
    Responder-->>Initiator: Message 4 (HDR, KE, Nr) <br> Key Exchange & Nonce

    note over Initiator, Responder: Shared Secret generated. Remaining messages are encrypted.

    Initiator->>Responder: Message 5 (HDR*, IDii, HASH_I) <br> Identification & Auth
    Responder-->>Initiator: Message 6 (HDR*, IDir, HASH_R) <br> Identification & Auth

    note over Initiator, Responder: IKE SA Established
```

Key derivation: `DeriveIKEv1Keys()` (RFC 2409 §5) → SKEYID, SKEYID_d/a/e.

---

## XAUTH (Extended Authentication)

Additional legacy auth step inside encrypted IKE SA for end-user VPN clients:

```mermaid
sequenceDiagram
    participant Initiator as VPN Client
    participant Responder as SWAN-NG (XAUTH)

    note over Initiator, Responder: Transaction Mode (XAUTH)

    Responder->>Initiator: Request Username / Password (ISAKMP_CFG)
    Initiator-->>Responder: Reply Username / Password
    Responder->>Initiator: XAUTH Success (or Failure)
    Initiator-->>Responder: XAUTH Acknowledge
```

---

## Quick Mode (Phase 2 — IPsec SA)

3 messages negotiate the actual ESP data tunnel after Phase 1 + XAUTH:

```mermaid
sequenceDiagram
    participant Initiator as VPN Client
    participant Responder as SWAN-NG (Quick Mode)

    note over Initiator, Responder: Quick Mode (Phase 2)

    Initiator->>Responder: Message 1 (HDR*, HASH1, SA, Ni, [KE], IDi, IDr)
    Responder-->>Initiator: Message 2 (HDR*, HASH2, SA, Nr, [KE], IDi, IDr)
    Initiator->>Responder: Message 3 (HDR*, HASH3)

    note over Initiator, Responder: Child SA Installed. ESP Traffic Begins.
```

---

## NAT-T in IKEv1

NAT detected via `NAT-D` payloads during Messages 3–4 of Main Mode. If detected, socket shifts from UDP 500 → UDP 4500 with ESP wrapped in UDP.
