# IKEv1 Workflow (Legacy IPsec)

SWAN-NG implements the IKEv1 (RFC 2409) state machine to ensure backward compatibility with legacy endpoints and appliances.

## IKEv1 State Machine (Main Mode)

In IKEv1, Phase 1 (ISAKMP SA) establishes the secure control channel using 6 messages in **Main Mode**.

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

## IKEv1 Extended Authentication (XAUTH)

For end-user VPN clients (like macOS built-in VPN or legacy Android clients), IKEv1 requires an additional legacy authentication step called **XAUTH**. This happens inside the encrypted IKE SA.

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

## Quick Mode (Phase 2 - IPsec SA)

Once Phase 1 and XAUTH are complete, SWAN-NG negotiates the actual ESP data tunnel using **Quick Mode** (3 messages).

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

## NAT-Traversal (NAT-T) in IKEv1

SWAN-NG detects if a client is behind a NAT router during Messages 3 and 4 of Main Mode using `NAT-D` payloads.
If a NAT is detected, SWAN-NG dynamically shifts the socket from **UDP 500** to **UDP 4500** and encapsulates ESP traffic in UDP.
