# LibreSWAN to SWAN-NG Porting Note & Architecture Guide

This document identifies core features present in the original LibreSWAN source code (`~/libreswan`) and provides explicit strategies on how to port those functionalities into the pure-Go, user-space architecture of SWAN-NG. It serves as our architectural design reference.

## 1. Data Plane & Encapsulation

**What exists in LibreSWAN:**
LibreSWAN relies on the OS kernel for the IPsec data plane. It interfaces with Linux XFRM (`kernel_xfrm.c`), PF_KEYv2 (`kernel_pfkeyv2.c`), and KLIPS. The kernel handles ESP packet encapsulation, decryption, and Security Policy Database (SPD) routing.

**How to port to SWAN-NG:**
Due to our strict `CGO_ENABLED=0` constraint and the goal of cross-platform user-space networking (avoiding kernel "Dirty Frag" bugs), we completely bypass OS kernel APIs.
- We use virtual TUN interfaces (e.g., `golang.zx2c4.com/wireguard/tun`) to ingest raw IP packets.
- We implement ESP encapsulation and decapsulation entirely in pure Go within the `internal/esp` package.
- We implement a User-Space Security Policy Database (SPD) to evaluate traffic selectors and route packets natively between the TUN interface and the ESP crypto engine.

## 2. Cryptography Engine

**What exists in LibreSWAN:**
LibreSWAN relies on Mozilla NSS (`crypto.c`, `nss_cert_verify.c`, `x509_ocsp.c`) and sometimes OpenSSL for cryptographic primitives (AES, SHA, DH) and X.509 certificate operations.

**How to port to SWAN-NG:**
- We strictly use Go's standard `crypto/*` and `golang.org/x/crypto/*` libraries.
- All AES-GCM, ChaCha20-Poly1305, ECDSA, RSA, and DH group operations must be implemented natively.
- No C-based external crypto modules or hardware offloading will be used unless exposed natively via Go's standard library.

## 3. Daemon Administration & Runtime Control

**What exists in LibreSWAN:**
LibreSWAN uses a Unix domain socket called "Whack" (`whack_add.c`, `whack_listen.c`, `whack_status.c`) which the `ipsec whack` CLI tool uses to dynamically add connections, query status, and control the `pluto` daemon without restarting it.

**How to port to SWAN-NG:**
- We replace the "Whack" socket with a declarative **Hot-Reloading** mechanism.
- SWAN-NG will use `fsnotify` to monitor `config.yaml` and the `profile.d/` directory for changes.
- A `hot_reload: true|false` configuration toggle will dictate this behavior. When enabled, the daemon automatically parses changes and synchronizes active connection states (spinning up new tunnels or tearing down removed ones gracefully).

## 4. Certificate Revocation (CRL/OCSP)

**What exists in LibreSWAN:**
Through NSS, LibreSWAN natively supports checking X.509 Certificate Revocation Lists (CRL) and querying Online Certificate Status Protocol (OCSP) responders (`x509_crl.c`, `x509_ocsp.c`).

**How to port to SWAN-NG:**
- Since SWAN-NG relies heavily on client certificates for IKEv2 endpoint authentication, we must build pure-Go CRL and OCSP verification.
- We will implement an HTTP-based fetcher for CRLs and an OCSP client to validate incoming certificate chains during the `IKE_AUTH` phase.

## 5. Post-Quantum Preshared Keys (PPK)

**What exists in LibreSWAN:**
LibreSWAN implements RFC 8784 (`ikev2_ppk.c`), allowing the use of Post-quantum Preshared Keys (PPK) to protect IKEv2 exchanges against future quantum computer attacks.

**How to port to SWAN-NG:**
- As a Next-Generation VPN operating in the quantum processing era, ensuring maximum security is a necessity.
- We will add PPK extension payloads to our IKEv2 parser/builder.
- We will integrate PPK into the key derivation function (PRF+) as defined in RFC 8784 to secure the `Child SA` key material.

## 6. Authentication Paradigms (XAUTH/EAP)

**What exists in LibreSWAN:**
LibreSWAN can plug into Linux PAM (`pam_auth.c`) to validate usernames and passwords for IKEv1 XAUTH and IKEv2 EAP.

**How to port to SWAN-NG:**
- We cannot use PAM due to the `CGO_ENABLED=0` restriction (PAM typically requires C bindings).
- Authentication must rely on credentials defined in YAML profiles (`profile.d/`).
- Future extensibility can be achieved by implementing pure-Go network clients for external directories like LDAP or RADIUS.

## 7. Dynamic DNS (DDNS) & Opportunistic Encryption

**What exists in LibreSWAN:**
LibreSWAN can initiate or update tunnels based on DNS resolution changes (`ddns.c`, `whack_ddns.c`) and supports Opportunistic IPsec (`labeled_ipsec.c`, `kernel_policy.c`).

**How to port to SWAN-NG:**
- We will add DDNS client support to periodically resolve hostnames and trigger MOBIKE address updates or session renegotiations natively.
- Opportunistic Encryption remains a backlog item for edge use-cases, as we prioritize static Site-to-Site and Roadwarrior profiles first.
