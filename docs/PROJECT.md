# SWAN-NG Project Information

## Overview
**SWAN-NG** (Secure Wide Area Network Next-Generation) is a secure, memory-safe, and highly portable next-generation IPsec VPN daemon. Built entirely in **pure Go** (`CGO_ENABLED=0`), it completely bypasses legacy OS kernel IPsec stacks (like Linux XFRM or Windows WFP) in favor of a 100% user-space network data plane.

## Key Features
- **Zero CGO & Standalone Binary:** Compiles without any C/C++ cross-compilation toolchains or OpenSSL dependencies. Uses Go's native `crypto` libraries.
- **User-Space ESP Data Plane:** Implements IPsec ESP (RFC 4303) processing inside the Go application using virtual TUN adapters, guaranteeing immunity from Dirty Frag and kernel vulnerabilities.
- **Integrated PPP & L2TP Server:** Fully-featured L2TP (RFC 2661) engine natively baked in to support legacy hardware, infrastructure firewalls (MikroTik, Palo Alto), and mobile devices without dedicated clients.
- **Dual-Protocol IKEv1 & IKEv2:** Natively supports both legacy IKEv1 key exchanges (RFC 2409) and modern IKEv2 (RFC 7296). Supports advanced authentication schemes (X.509 Certificates, EAP-MSCHAPv2, PSK, XAUTH).
- **Universal Topology:** Supports acting as a Server (Responder), Client (Initiator), or establishing direct Site-to-Site tunnels natively.
- **TCP Encapsulation Fallback:** Binds standard UDP ports (500, 4500, 1701), but features native support for TCP Encapsulation of IPsec (RFC 8229) for highly restrictive corporate firewalls.
- **Hot-Reloading:** Watchers (`fsnotify`) are integrated to allow modifying user profiles and configurations dynamically without restarting active IPsec sockets.

## Security Model
1. **User-Space Isolation:** A compromised kernel IPsec driver cannot lead to remote code execution within SWAN-NG. The application safely handles corrupted, malformed, or injected IP packets via pure Go bounds-checked logic.
2. **Buffer Pooling:** Utilizes `sync.Pool` to reuse byte slices. A heavy network flood cannot trigger an Out-Of-Memory (OOM) crash by allocating an unbounded number of objects.
3. **Graceful Failures:** Cryptographic failures result in silently dropped packets to thwart replay and timing attacks, never panicking the application loop.
