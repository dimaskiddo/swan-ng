# SWAN-NG — UDP/TCP Encapsulation

All traffic encapsulated in Layer 4 (UDP/TCP) — raw IP Protocol 50 (ESP) not used at OS socket level.

---

## Standard Port Bindings

```mermaid
graph LR
    Client((VPN Client))

    Client -->|IKE_SA_INIT| UDP500[SWAN-NG UDP 500]
    Client -->|IKE_AUTH + ESP| UDP4500[SWAN-NG UDP 4500]
    Client -.->|L2TP over IPsec| UDP1701[SWAN-NG UDP 1701]
```

| Port | Protocol | Usage |
|---|---|---|
| UDP 500 | IKE | Initial IKEv1/IKEv2 negotiations |
| UDP 4500 | NAT-T / ESP | NAT-Traversal: encrypted ESP data + subsequent IKE packets |
| UDP 1701 | L2TP | L2TP/PPP session establishment |

---

## NAT-Traversal (UDP 4500)

NAT detected during UDP 500 handshake → all subsequent communication shifts to UDP 4500 → ESP packets prepended with 4-byte empty UDP header.

### Packet Demux (UDP:4500)

```mermaid
flowchart TD
    Pkt["UDP:4500 packet arrives"] --> Classify["esp.ClassifyNATT(buf)"]
    Classify --> Check{Non-ESP Marker<br/>4 zero bytes?}
    Check -- "Marker present" --> IKE["IKE packet<br/>→ ikeServer.HandlePacket(payload, isNATT=true)"]
    Check -- "No marker" --> ESP["ESP packet<br/>→ espEngine.HandleInboundESP(buf)"]
```

Non-ESP Marker (4 zero bytes) prepended to IKE packets on UDP 4500, distinguishing them from ESP packets (which start directly with the SPI field).

---

## TCP Fallback (RFC 8229)

For restrictive firewalls blocking all UDP — IKE and ESP packets framed over TCP stream with length prefix.

**Not implemented** — config fields `enable-tcp`, `tcp-remoteport` defined but no TCP listener code.

### TCP Workflow

```mermaid
sequenceDiagram
    participant Client as VPN Client
    participant FW as Restrictive Firewall
    participant Server as SWAN-NG (TCP 4500)

    Client->>FW: UDP 500 Request
    FW--xClient: DROP (UDP Blocked)

    note over Client: Client detects UDP failure and falls back to TCP

    Client->>Server: TCP SYN (Port 4500)
    Server-->>Client: TCP SYN-ACK
    Client->>Server: TCP ACK (Connection Established)

    Client->>Server: Send IKE_SA_INIT framed with Length Prefix
    Server-->>Client: Reply IKE_SA_INIT framed with Length Prefix

    note over Client, Server: Entire ESP data stream flows over the TCP stream using Length Prefixes.
```

### TCP Stream Framing

Every packet prefixed with 16-bit length integer for correct boundary slicing from the continuous TCP stream buffer.

```mermaid
packet-beta
title RFC 8229 TCP Stream Framing
0-15: "Length Prefix (16-bit)"
16-63: "Original IKE or ESP Packet Payload"
```
