# Client-Server Communication Topologies

SWAN-NG is designed to be a universal VPN daemon, meaning the exact same binary can act as a server, a client, or a peer in a site-to-site topology.

## 1. IKEv2 End-User Topology

This is the standard topology for modern mobile clients (iOS, macOS, Android StrongSwan, Windows IKEv2) connecting to the central SWAN-NG VPN server.

```mermaid
graph TD
    subgraph "End-User Devices"
        iOS["iOS Device<br/>(IKEv2 Built-in)"]
        Win["Windows 11<br/>(IKEv2 Built-in)"]
    end
    
    Internet(("Internet"))
    
    subgraph "Datacenter / Cloud"
        SWAN["SWAN-NG Responder<br/>(UDP 500/4500)"]
        InternalNet["Internal Subnet (10.0.0.0/24)"]
    end
    
    iOS --> Internet
    Win --> Internet
    Internet --> SWAN
    SWAN --> InternalNet
```

### Communication Flow:
1. Client requests a connection on UDP 500.
2. IKE_SA_INIT and IKE_AUTH complete.
3. SWAN-NG assigns a virtual IP (e.g. `10.0.0.100`) from its internal IPAM pool to the client.
4. Client traffic is encapsulated in ESP over UDP 4500.

## 2. Site-to-Site Topology

In this scenario, two offices are securely bridged. Both sides run SWAN-NG. One is configured as `right=%any` (Responder), and the other has `right=Public_IP` (Initiator).

```mermaid
graph LR
    subgraph "Office A (Initiator)"
        SubA["Subnet A (10.1.0.0/16)"]
        SWAN_A["SWAN-NG Node A"]
    end
    
    Internet(("Internet"))
    
    subgraph "Office B (Responder)"
        SWAN_B["SWAN-NG Node B"]
        SubB["Subnet B (10.2.0.0/16)"]
    end
    
    SubA <--> SWAN_A
    SWAN_A <-->|ESP Tunnel| Internet
    Internet <-->|ESP Tunnel| SWAN_B
    SWAN_B <--> SubB
```

### Communication Flow:
1. Node A (Initiator) boots and reads its configuration.
2. It actively contacts Node B on UDP 500.
3. They authenticate (usually via Pre-Shared Key).
4. Node A routes `10.2.0.0/16` into its TUN interface. Node B routes `10.1.0.0/16` into its TUN interface.
5. All traffic between subnets is transparently encrypted by ESP.

## 3. L2TP over IPsec Topology (Infrastructure Compatibility)

Layer 2 Tunneling Protocol (L2TP) is frequently used by infrastructure hardware (MikroTik routers, Palo Alto firewalls) and legacy OS endpoints.
L2TP lacks inherent security, so it is strictly encapsulated *inside* an IPsec tunnel.

### L2TP Data Workflow

```mermaid
sequenceDiagram
    participant Client as L2TP/IPsec Client
    participant IPsec as SWAN-NG (IKEv1 & ESP)
    participant L2TP as SWAN-NG (L2TP Engine)
    
    note over Client, L2TP: Phase 1: Secure the Tunnel (IPsec)
    Client->>IPsec: IKEv1 Main Mode & Quick Mode
    IPsec-->>Client: IPsec ESP Tunnel Established
    
    note over Client, L2TP: Phase 2: Establish the L2TP Control Channel
    Client->>L2TP: Start-Control-Connection-Request (SCCRQ) <br/> [Encrypted inside ESP]
    L2TP-->>Client: Start-Control-Connection-Reply (SCCRP)
    Client->>L2TP: Start-Control-Connection-Connected (SCCCN)
    
    note over Client, L2TP: Phase 3: Setup L2TP Data Session
    Client->>L2TP: Incoming-Call-Request (ICRQ)
    L2TP-->>Client: Incoming-Call-Reply (ICRP)
    Client->>L2TP: Incoming-Call-Connected (ICCN)
    
    note over Client, L2TP: Phase 4: PPP Negotiation
    Client->>L2TP: LCP Configuration Request (PPP Framing)
    L2TP-->>Client: LCP Configuration Ack
    
    note over Client, L2TP: Authentication
    L2TP->>Client: CHAP Challenge
    Client-->>L2TP: CHAP Response (Username/Password)
    L2TP->>Client: CHAP Success
    
    note over Client, L2TP: IP Assignment
    Client->>L2TP: IPCP Request IP Address
    L2TP-->>Client: IPCP Ack (Assigns 10.0.0.101 from IPAM)
    
    note over Client, L2TP: Final State: L2TP Traffic flows inside UDP 1701, which is encrypted inside ESP over UDP 4500.
```

### Authentication Isolation

In the L2TP over IPsec topology, authentication is strictly split into two layers:
1. **Machine Authentication (IPsec):** Validated via a Pre-Shared Key (PSK) configured in the `ipsec.d/` connection block.
2. **User Authentication (L2TP/PPP):** Validated via CHAP credentials configured in the `profile.d/` blocks. Multiple users can share the same IPsec connection, but are isolated by their unique PPP credentials.
