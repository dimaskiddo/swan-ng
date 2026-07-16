# SWAN-NG — IKEv2

IKEv2 (RFC 7296) — modern, mobile-friendly, establishes control channel + data tunnel in 4 messages.

---

## SA_INIT & IKE_AUTH

```mermaid
sequenceDiagram
    participant Initiator as IKEv2 Client
    participant Responder as SWAN-NG (IKEv2 Engine)

    note over Initiator, Responder: IKE_SA_INIT (Phase 1)

    Initiator->>Responder: Message 1 (HDR, SAi1, KEi, Ni) <br> Propose Crypto, DH Key, Nonce
    Responder-->>Initiator: Message 2 (HDR, SAr1, KEr, Nr, [CERTREQ]) <br> Accept Crypto, DH Key, Nonce

    note over Initiator, Responder: IKE SA Established (SKEYSEED). Following messages are Encrypted.

    note over Initiator, Responder: IKE_AUTH (Phase 2 & Authentication)

    Initiator->>Responder: Message 3 (HDR*, SK {IDi, [CERT,] [CERTREQ,] [IDr,] AUTH, SAi2, TSi, TSr}) <br> Authenticate self, Propose IPsec SA
    Responder-->>Initiator: Message 4 (HDR*, SK {IDr, [CERT,] AUTH, SAr2, TSi, TSr}) <br> Authenticate self, Accept IPsec SA

    note over Initiator, Responder: Child SA Installed. ESP Traffic Begins.
```

Key derivation: `DeriveIKEv2Keys()` (RFC 7296 §2.14) → SK_d, SK_ai/ar, SK_ei/er, SK_pi/pr.
Child SA keys: `DeriveChildSAKeys()` (RFC 7296 §2.17) → KEYSRC/KEYMAT.

SessionManager bridges to ESP: `InstallV2ChildSA()` → creates `esp.SecurityAssociation` + installs into `esp.Engine` SPD.

---

## EAP Authentication

For enterprise scenarios — IKE_AUTH extends to carry EAP messages before final IPsec SA authorization:

```mermaid
sequenceDiagram
    participant Initiator as VPN Client
    participant Responder as SWAN-NG (IKEv2 / EAP Engine)

    note over Initiator, Responder: IKE_SA_INIT completed previously

    Initiator->>Responder: IKE_AUTH (Request: IDi, SAi2, TSi, TSr) <br> Omits AUTH payload to trigger EAP
    Responder-->>Initiator: IKE_AUTH (Response: IDr, CERT, AUTH, EAP-Request/Identity)

    Initiator->>Responder: IKE_AUTH (Request: EAP-Response/Identity)
    Responder-->>Initiator: IKE_AUTH (Response: EAP-Request/MSCHAPv2)

    Initiator->>Responder: IKE_AUTH (Request: EAP-Response/MSCHAPv2 Challenge)
    Responder-->>Initiator: IKE_AUTH (Response: EAP-Success)

    Initiator->>Responder: IKE_AUTH (Request: AUTH) <br> Client proves it has the EAP key
    Responder-->>Initiator: IKE_AUTH (Response: AUTH, SAr2, TSi, TSr) <br> Final IPsec SA
```

Supported EAP methods: EAP-MSCHAPv2 (RFC 2759), EAP-TLS (RFC 5216).

---

## MOBIKE (RFC 4555)

Seamless network handover (Wi-Fi ↔ Cellular) without re-authentication — client IP updated via INFORMATIONAL with `UPDATE_SA_ADDRESSES`.

**Partial:** NotifyType constant + config field defined, no handler implemented yet.

```mermaid
sequenceDiagram
    participant Client as VPN Client (Smartphone)
    participant Responder as SWAN-NG (Responder)

    note over Client, Responder: Initial Connection (Wi-Fi IP: 192.168.1.5)
    Client->>Responder: IKE_SA_INIT & IKE_AUTH
    Responder-->>Client: ESP Data Tunnel Established

    note over Client: Client leaves Wi-Fi, switches to Cellular (New IP: 10.50.2.10)

    note over Client, Responder: MOBIKE IP Update
    Client->>Responder: INFORMATIONAL (HDR, SK {UPDATE_SA_ADDRESSES})
    Responder-->>Client: INFORMATIONAL (HDR, SK {}) <br> Acknowledgement

    note over Client, Responder: ESP Tunnel dynamically shifted to 10.50.2.10
```
