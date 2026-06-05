# IKEv2 Workflow (Next-Generation IPsec)

SWAN-NG prioritizes the modern IKEv2 (RFC 7296) state machine for robust, mobile-friendly (MOBIKE), and highly secure deployments.
IKEv2 is significantly more efficient than IKEv1, establishing both the control channel and the data tunnel in just 4 messages.

## The IKEv2 State Machine (IKE_SA_INIT & IKE_AUTH)

Every IKEv2 connection follows two distinct phases inside a single fast sequence.

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

## Advanced Authentication (EAP)

For enterprise scenarios, SWAN-NG supports EAP (Extensible Authentication Protocol) over IKEv2.
When EAP is used, the `IKE_AUTH` phase extends to carry EAP messages back and forth before the final IPsec SA is authorized.

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

## MOBIKE (RFC 4555)

SWAN-NG supports MOBIKE to allow clients (like smartphones) to seamlessly switch between Wi-Fi and Cellular networks without dropping the VPN connection.

Even though the full implementation phase for MOBIKE has not yet started, the architectural design ensures that when the client's IP changes, it simply sends an `INFORMATIONAL` packet with an `UPDATE_SA_ADDRESSES` payload from its new IP. SWAN-NG verifies the packet mathematically and dynamically updates the ESP tunnel endpoint without forcing a re-authentication.

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
