# SWAN-NG — Agent Instructions

User-space IPsec VPN in Go: ESP data plane, IKEv1/IKEv2 control plane, L2TPv2. Single static binary (`CGO_ENABLED=0`). Never guess protocol logic — ask when ambiguous.

---

## Workflow Rules

1. Read `TASKS.md` before every session to orient to current state.
2. Never rework items marked `[x]` in `TASKS.md` unless explicitly instructed.
3. Update `TASKS.md` immediately after completing a task.
4. Never attempt to write the entire codebase in a single response.

## Skills & Caveman Mode

- **GLOBAL:** All prompts processed as if `"Use caveman mode full"` is injected.
- Before ANY coding task, invoke and read: `using-superpowers`, `karpathy-guidelines`, `caveman`.
- Use `using-superpowers` to route to other relevant skills per task.

---

## Architecture

| Component | Role |
|---|---|
| **ESP** | User-space ESP data plane — AEAD/CBC encryption, SADatabase, anti-replay, NAT-T, PMTU, sync.Pool buffers |
| **IKE** | IKEv1 + IKEv2 control plane — state machines, DH, proposals, EAP, DPD, fragmentation, retransmission |
| **L2TP** | L2TPv2 LNS server — tunnel/session state, PPP framing, LCP, CHAP-MD5, IPCP, reliable delivery |
| **TUN** | Platform-agnostic TUN device via `wireguard/tun`. ReadPacket/WritePacket. Linux/macOS/Windows |
| **Listener** | UDP manager — binds ports 500 (IKE), 4500 (NAT-T/ESP), 1701 (L2TP). Per-port goroutines |
| **IPAM** | Bitmap-based IPv4 pool. Range: `"startIP - endIP"`, max 65536. Separate pools for IKEv2 and L2TP |
| **Certman** | PKI — ECDSA P-384 CA/server/client certs. Export: .p12, .mobileconfig, .sswan, .txt |
| **Config** | YAML via viper. Exe-relative path resolution. fsnotify watcher for hot-reload |
| **Log** | `log/slog` + lumberjack rotation. Dual output (stdout + file) |

## CLI

```
swan-ng [--config <path>]
  daemon                  # Start VPN daemon (TUN + UDP 500/4500/1701 + ESP + IKE + L2TP)
  ikev2
    add-user <username>   # Generate client cert, export .p12/.mobileconfig/.sswan
  l2tp
    add-user <username>   # Masked password prompt, write profile.d/ + .txt export
  service
    install               # Register OS service (systemd/launchd/SCM)
    uninstall             # Remove OS service
  version                 # Print version + commit hash
```

---

## Critical Constraints

### Build — Pure Go
- `CGO_ENABLED=0` always. No C/C++ toolchains, no OpenSSL. All crypto via Go stdlib.

### User-Space Only
- No kernel IPsec APIs (XFRM, PF_KEYv2, WFP). TUN interfaces for all packet I/O.
- ESP encryption/decryption entirely in Go: `crypto/aes` + `crypto/cipher` (AES-GCM, ChaCha20-Poly1305).

### Ports
- UDP 500 (IKE), UDP 4500 (NAT-T + ESP), UDP 1701 (L2TP).
- TCP 4500 (RFC 8229): config fields defined, not yet implemented.

### Operation Modes
- Server (Responder), Client (Initiator), Site-to-Site. Multiple concurrent connections over shared/distinct TUN interfaces.

### Configuration
- YAML via `spf13/viper`. Maps LibreSWAN `ipsec.conf(5)` parameters into `config.yaml`.
- Default path: relative to executable (`os.Executable()`), NOT CWD.
- Multiple named connections under `ipsec: connections:`.
- PSK in connection blocks, NOT in `l2tp:` profiles.
- Hot-reload via fsnotify on `ipsec.d/` and `profile.d/`.

### CLI & User Management
- `spf13/cobra` CLI. All commands accept `--config <path>`.
- `swan-ng ikev2 add-user`: interactive prompts, ECDSA P-384 cert gen, profile export (.p12, .mobileconfig, .sswan).
- `swan-ng l2tp add-user`: masked password prompt via `x/term`, profile.d YAML + .txt export.
- IKEv2: strict single connection per identity/certificate.
- L2TP: multiple concurrent connections per credential.

### Cross-Platform
- `filepath.Join()` everywhere. No hardcoded paths.
- TUN: `wireguard/tun` (Wintun on Windows).
- Service: `kardianos/service` (systemd/launchd/SCM).

### Logging
- `log/slog` only. No `fmt.Println` or `log.Fatal` in core packages.
- `lumberjack` for rotation. Rotation params bound to config.

### Context & Concurrency
- `context.Context` as first param for long-running functions.
- Graceful shutdown via OS signals + context cancellation.
- `sync.Mutex`/`sync.RWMutex` on all shared state.
- `errgroup` / `sync.WaitGroup` — no goroutine leaks.

### Memory Efficiency
- `sync.Pool` (`esp.BufferPool`) for all packet buffers. `clear()` on Get.
- Never allocate new byte slices per packet.

### Streaming I/O
- Never `os.ReadFile` on target files. Use `os.Open` + `io.Reader` / `bufio.Scanner` for chunked processing. Keep memory minimal during walks.

### Error Handling
- `fmt.Errorf("context: %w", err)` wrapping. Security paths log at Debug/Warn, silently drop — never panic.

### No Stubbing
- Every function must be complete and production-ready. No `// TODO`, `// rest of code`, or placeholder logic.

### Dependencies
- Stdlib first. Approved third-party: `wireguard/tun`, `fsnotify`, `lumberjack`, `go-pkcs12`, `x/term`, `cobra`, `viper`, `yaml.v3`, `uuid`.

### Build Artifacts
- Output to `dist/` via Makefile. Integration tests validate compiled binary.

---

## Non-Negotiable Rules

1. **No stubs.** Every file complete, production-ready.
2. **No guessing** on protocol logic, RFC steps, or cryptographic derivation. Pause, state ambiguity, ask.
3. **Never auto-run pipeline.** Provide exact command + expected output, wait for user.
4. **No system temp dirs.** Runtime files in configured paths only.

---

## Directory Tree

```
swan-ng/
├── cmd/swan-ng/              # Entry: cobra CLI (main, daemon, ikev2, l2tp, service, version)
├── internal/
│   ├── certman/              # PKI: CA, server/client certs, .p12/.mobileconfig/.sswan exports
│   ├── config/               # Viper YAML config, exe-relative path resolution, fsnotify watcher
│   ├── esp/                  # ESP data plane: AEAD/CBC, SADatabase, anti-replay, NAT-T, PMTU
│   ├── ike/                  # IKEv1 + IKEv2: state machines, DH, key derivation, EAP, DPD, frag
│   ├── ipam/                 # Bitmap-based IPv4 address pool
│   ├── l2tp/                 # L2TPv2 LNS: tunnel/session, PPP, LCP, CHAP, IPCP
│   ├── listener/             # UDP listener manager (ports 500/4500/1701)
│   ├── log/                  # slog wrapper + lumberjack rotation
│   └── tun/                  # TUN device via wireguard/tun (Linux/macOS/Windows)
├── docs/
│   ├── ARCHITECTURE.md       # Module map, component details, wire formats
│   ├── WORKFLOWS.md          # Pipeline flows, stage details, error recovery
│   └── WORKFLOW_*.md         # Detailed protocol-specific deep-dives
├── dist/                     # Build output
├── config.yaml.example       # Full annotated config template
├── TASKS.md                  # Implementation tracker — read before every session
├── Makefile                  # Build targets
├── .goreleaser.yml           # Cross-platform release config
└── Dockerfile                # Multi-stage build
```

---

## References

| File | Purpose |
|---|---|
| `config.yaml.example` | Full annotated config reference |
| `docs/ARCHITECTURE.md` | Module map, component internals, data flows |
| `docs/WORKFLOWS.md` | Pipeline flow diagrams, operational sequences |
| `TASKS.md` | Current project state — read before every session |
| `Makefile` | Build targets and cross-compilation |
| `.goreleaser.yml` | Release configuration (darwin/linux/windows × 386/amd64/arm64) |
| `internal/esp/` | ESP data plane — engine, packet, cipher, SA, NAT-T, anti-replay |
| `internal/ike/` | IKEv1 + IKEv2 — state machines, key derivation, EAP, DPD, fragmentation |
| `internal/l2tp/` | L2TPv2 — tunnel/session, PPP, LCP, CHAP, IPCP, profile loader |
| `internal/config/` | YAML config types, loader, fsnotify watcher |
| `internal/certman/` | PKI — CA, server/client certs, .p12/.mobileconfig/.sswan exports |
| `internal/tun/` | TUN device abstraction (Linux/macOS/Windows) |
| `internal/listener/` | UDP listener manager (ports 500/4500/1701) |
| `internal/ipam/` | Bitmap-based IPv4 address pool |
| `internal/log/` | slog wrapper + lumberjack rotation |
