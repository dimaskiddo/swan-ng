# Secure Wide Area Network (S/WAN) Next-Generation (SWAN-NG) IPsec VPN AI Agent Instructions

## 🎯 Role & Objective
You are an expert network protocol engineer, cryptographer, and Golang software architect. Your task is to rewrite traditional IPsec daemon functionality (resembling LibreSWAN / StrongSWAN) into a modern, Next-Generation Golang application (`SWAN-NG`). This application will prioritize providing a robust user-space IPsec ESP data plane first, followed by L2TP over IPsec for infrastructure compatibility, and finally IKEv1 and IKEv2 for client endpoints. The result must be a secure, memory-safe, and highly portable single binary.

## 📁 Directory Context
- **Current Directory (`./`)**: The root of the new `SWAN-NG` Golang project.

## 📋 Workflow & Task Tracking
- Always check `TASKS.md` before starting a new session to understand the current project state.
- **Skill Check:** Actively identify and load any relevant globally installed skills required for the active task before proceeding.
- **NEVER** rework, refactor, or touch items in `TASKS.md` marked as done (`[x]`) unless explicitly instructed by the human engineer.
- Update `TASKS.md` automatically when a task is completed.

## 🛠️ Skills & Utilization (CRITICAL)
**🔥 GLOBAL OVERRIDE DIRECTIVE:** Every single prompt, interaction, and task execution MUST be processed as if "Use caveman mode full" has been explicitly injected. You must operate strictly under the constraints of "caveman mode full" at all times.

You are equipped with the Obra/Superpowers framework and Andrej Karpathy guidelines, located globally in `~/.gemini/antigravity/skills/`. You MUST NOT rely solely on your internal training data for workflows, debugging, or complex tasks.

1. **The Boot Sequence:** Before beginning ANY task in this workspace, your very first action MUST be to invoke and read the `using-superpowers`, `karpathy-guidelines`, and `caveman` skills. These act as your foundational operating procedures.
2. **Skill Routing:** Once you have processed those baselines, use the `using-superpowers` framework to identify and load other relevant skills based on the active task.
3. **Plan-Validate-Execute:**
  - **Plan:** Explicitly state in your response that you have loaded `using-superpowers`, `karpathy-guidelines`, `caveman`, and any other required task-specific skills, and confirm that "caveman mode full" is active.
  - **Validate:** Ensure the loaded skills' directives do not conflict with the project's "Strict Architectural Constraints."
  - **Execute:** Perform the task using the exact methodologies prescribed by the loaded skills.

## 🏗️ Strict Architectural Constraints

### 1. Pure Golang (CGO_ENABLED=0)
- The application MUST be strictly compiled with `CGO_ENABLED=0`. 
- No C/C++ cross-compilation toolchains, no OpenSSL dependencies, no `certutil`, and no OS-specific kernel headers. The resulting binary must be a static, standalone executable. All cryptography and certificate generation must utilize Go's standard `crypto` library.

### 2. IPsec Priority: User-Space Data Plane & Dirty Frag Immunity
- To achieve true cross-platform capability and immunize the application against Linux kernel `esp4`/`esp6`/`rxrpc` vulnerabilities (Dirty Frag), you must **NOT** use OS-native IPsec kernel APIs (XFRM, PF_KEYv2, or WFP).
- **Virtual Interfaces:** Utilize virtual TUN interfaces (e.g., `golang.zx2c4.com/wireguard/tun`) to ingest raw IP packets from the OS in user-space.
- **ESP Encapsulation:** Implement IPsec ESP (Encapsulating Security Payload - RFC 4303) encryption/decryption entirely in pure Go using `crypto/aes` and `crypto/cipher` (AES-GCM / ChaCha20-Poly1305). This is the foundational priority.
- **Standard RFC Ports & TCP Fallback:** The application MUST bind to the standard UDP ports: **UDP Port 4500** (IPsec NAT-T and UDP-Encapsulated ESP per RFC 3948), **UDP Port 1701** (L2TP per RFC 2661), and **UDP Port 500** (IKEv2 Control - RFC 7296). Furthermore, the application MUST implement RFC 8229 to support TCP Encapsulation of IPsec and IKE packets on **TCP Port 4500** as a reliable fallback mechanism for highly restrictive firewalls blocking UDP traffic.

### 3. Universal Operation Modes & Concurrent Topologies
- The application architecture must be inherently flexible, capable of operating natively as:
  - **Server (Responder):** Accepting incoming client connections.
  - **Client (Initiator):** Connecting out to remote gateways.
  - **Site-to-Site:** Establishing peer-to-peer tunnels.
- **Concurrent Execution:** The core engine MUST be capable of parsing, establishing, and multiplexing **multiple concurrent, distinct IPsec connections** (e.g., listening for generic endpoints while simultaneously maintaining dedicated site-to-site tunnels) over shared or distinct virtual TUN interfaces based on the parsed configuration.

### 4. Configuration Modularity, IPAM & Feature Toggles
- Map standard LibreSWAN/StrongSWAN configuration structures into a modern, structured YAML format (`config.yaml`), prioritizing the global IPsec configurations first.
- **Executable-Relative Configuration Default:** By default, the application MUST resolve the location of `config.yaml` relative to the directory where the `swan-ng` executable actually resides (using `os.Executable()`), NOT the user's current working directory (`os.Getwd()`).
- **Comprehensive IPsec Parameter Mapping (Multi-Connection Support):** The `config.yaml` parser MUST support defining multiple named IPsec connections (mirroring legacy `conn <name>` blocks). These MUST be mapped as a key-value dictionary under `ipsec: connections:`. For exact definitions and default behaviors of these legacy parameters, you MUST strictly refer to the official manual at: **https://libreswan.org/man/ipsec.conf.5.html**
- **PSK Isolation Rule:** Pre-Shared Keys (PSKs) MUST be defined securely inside their respective named connection blocks under `ipsec: connections: <conn_name>: psk:`. They MUST NOT be placed inside the `l2tp:` user profiles.
- **Feature Toggles:** The `config.yaml` file MUST include distinct global feature flags to enable or disable target features natively.
- **Internal IPAM pools:** An Internal IP Pool Manager (IPAM) must be implemented natively inside the Go binary. The address range must be defined dynamically.
- **Network Defaults:** By default, if a client requests DNS assignment, the internal engine must assign Cloudflare DNS addresses (**1.1.1.1** and **1.0.0.1**).
- **Modular Profile Storage:** User and connection configurations must be modularized into a separate `profile.d/` directory. Example hierarchy (IPsec -> L2TP -> IKEv2):
  
  logging:
    level: "info"
    output: "file"
    file: "/var/log/swan-ng.log"
    max_size: 10
    max_backups: 5
    max_age: 7
    compress: true

  ipsec:
    connections:
      # Connection 1: Generic L2TP/IPsec Responder
      l2tp-responder:
        left: "%defaultroute"
        leftid: "<host_server_public_ip>"
        right: "%any"
        authby: "secret"
        psk: "<pre_shared_key>"
      
      # Connection 2: Dedicated Site-to-Site Tunnel
      office-s2s:
        left: "<host_server_public_ip>"
        right: "<office_public_ip>"
        authby: "secret"
        psk: "<site_to_site_psk>"

  ikev2:
    profile:
      - profile.d/ikev2-username.yaml

  l2tp:
    profile:
      - profile.d/l2tp-username.yaml

- Create a robust configuration manager using a pure-Go library (e.g., `gopkg.in/yaml.v3` or `github.com/spf13/viper`).

### 5. CLI, User Management & Connection Lifecycles
- Build a robust CLI interface using `github.com/spf13/cobra` or the native `flag` package.
- **Global Configuration Flag:** All subcommands MUST accept a persistent `--config <path>` flag. If provided, this path fully overrides the default executable-relative `config.yaml` path.
- **Hot-Reloading Capabilities:** Implement zero-downtime hot-reloading. The application must expose configurations to watch and parse modifications inside `profile.d/` on-the-fly (via `fsnotify`).
- **Target Audience Segmentation & Purpose Isolation (Prioritized):**
  - `swan-ng daemon [--config path]` (starts the resident VPN monitor, TUN interface, and UDP/TCP listeners)
  - **L2TP over IPsec Mode (Targeting Infrastructure Appliances: MikroTik, Palo Alto Firewalls, etc.):**
    - Mandated Command: `swan-ng l2tp add-user <username> [--config path]`
    - **Authentication Isolation:** Must utilize a multi-stage workflow where the IPsec tunnel is validated via the designated **IPsec PSK** (from a specific connection block), and the L2TP layer is validated via individual PPP CHAP user credentials.
    - **Interactive & Masked Prompts:** Must interactively prompt the administrator for the user's L2TP/PPP password, ensuring input characters are securely **masked/hidden**.
    - **Profile Export:** Must generate a structured `.txt` distribution profile containing the remote Server Domain/IP, the target L2TP Username, the matching unmasked L2TP Password, and the applicable IPsec PSK read from the `ipsec:` configuration block.
    - **Session Lifecycle:** Allow **multiple active client connections** across the exact same L2TP credentials concurrently.
  - **IKEv2 Mode (Targeting End-User Clients and Site-to-Site Tunnels):** - Mandated Command: `swan-ng ikev2 add-user <username> [--config path]`
    - Must support Certificate, EAP, and Pre-Shared Key (PSK) authentication to accommodate both client endpoints and site-to-site tunnels.
    - **Interactive Prompts:** Prompt administrator for certificate validity period (defaulting to 120 months).
    - **Auto-Generation:** Automatically generate the X.509 client certificate and private key in pure Go.
    - **Profile Export:** Export cross-platform client configurations (`.p12`, `.mobileconfig`, `.sswan`).
    - **Strict Session Isolation:** Enforce a strict **Single Connection per Identity/Certificate** constraint. 
  - `swan-ng service install [--config path]` (Automates service registration)
  - `swan-ng service uninstall [--config path]`

### 6. Cross-Platform Compatibility
- Ensure all networking primitives and TUN interface setups gracefully handle differences between Windows, macOS, and Linux.
- The binary must compile via simple `GOOS` and `GOARCH` flags and run identically across operating systems.

### 7. Project Layout & Idiomatic Go
- Follow the Standard Go Project Layout.
- **`cmd/swan-ng/`**: Contains the main application entry point.
- **`internal/`**: Contains private core code (e.g., `esp`, `ipsec`, `l2tp`, `ikev2`, `tun`, `crypto`, `config`) to prevent external importing.
- **`pkg/`**: Contains pure-Go API definitions if exposing embeddable VPN functionality to other Go projects.
- Use idiomatic Go naming conventions.

### 8. Observability & Network Logging
- **No `fmt.Println` or `log.Fatal` in core packages.**
- Use Go 1.21+'s native `log/slog` for structured, leveled logging (Debug, Info, Warn, Error).
- **Log Rotation & File Output:** The application MUST output logs to a file and integrate `github.com/natefinch/lumberjack` to provide automatic log rotation. Rotation parameters (such as `MaxSize`, `MaxBackups`, `MaxAge`, and `Compress`) MUST be bound dynamically to the `config.yaml` settings.
- Security Associations (SA), Key exchanges, and dropped packets should be logged with rich contextual attributes (Source IP, SPI, Protocol). Evicted/terminated duplicate sessions must be explicitly logged at the `Info` level.

### 9. Context & Concurrency
- Pass `context.Context` as the first parameter to any long-running or blocking function (e.g., UDP/TCP listeners, packet processing loops).
- Ensure graceful shutdowns. The daemon must intercept OS signals (`SIGINT`, `SIGTERM`) and use context cancellation to safely tear down TUN interfaces, send protocol DELETE payloads to peers, and close sockets.
- Manage goroutines carefully. High-throughput packet handling requires tight goroutine supervision to avoid leaks under heavy network load.

### 10. Memory Efficiency & High-Throughput Packet Processing
- **Never allocate new byte slices for every single network packet.**
- You MUST use `sync.Pool` to maintain a pool of reusable byte buffers for reading from the TUN interface and UDP/TCP sockets.
- Minimize garbage collection (GC) pressure to maintain high network throughput. 

### 11. Complete Code Generation (No Stubbing)
- **NEVER** use placeholders like `// ... rest of the code`, `// TODO`, or `// implement payload parser here` in your generated code.
- Always write complete, fully functional, and production-ready functions. If a cryptographic handshake or state machine is too long for one response, stop and ask the user to let you continue.

### 12. Protocol & Error Resiliency (Prioritized)
- In user-space networking, packets will arrive out of order, malformed, or corrupted.
- **IPsec / ESP:** The `esp` engine must **never** panic or crash due to an invalid cryptographic signature, unexpected packet size, or replay attack. Log the failure at `Debug` or `Warn` and silently drop the packet.
- **TCP Encapsulation:** Correctly parse standard ESP and IKE headers encapsulated in TCP streams as dictated by **[RFC 8229 (TCP Encapsulation)](https://datatracker.ietf.org/doc/html/rfc8229)**.
- **L2TP Interoperability:** Ensure the L2TP engine correctly implements control and data packet sequencing according to **[RFC 2661 (L2TP)](https://datatracker.ietf.org/doc/html/rfc2661)** over the established IPsec layer.
- **IKEv1 Interoperability:** Ensure the IKEv1 state machine correctly track standard protocol messages according to **[RFC 2409 (IKEv1)](https://datatracker.ietf.org/doc/html/rfc2409)**.
- **IKEv2 Interoperability:** Ensure the IKEv2 state machine correctly track standard protocol messages according to **[RFC 7296 (IKEv2)](https://datatracker.ietf.org/doc/html/rfc7296)**.
- **MOBIKE Support:** The engine MUST implement **[RFC 4555 (MOBIKE)](https://datatracker.ietf.org/doc/html/rfc4555)** natively.

### 13. Dependency Discipline
- Rely on the Go Standard Library (`stdlib` and `golang.org/x/crypto`) whenever possible.
- Third-party dependencies are severely restricted. Any new dependency must be completely free of CGO. Approved libraries include `software.sslmate.com/src/go-pkcs12` (for cert generation), `golang.org/x/term` (for password masking), and `github.com/natefinch/lumberjack` (for log rotation).

### 14. Build Artifacts & Integration Testing
- **Build Output:** All compilation steps must output the final executable(s) into a dedicated `dist/` directory at the project root.
- **Compiled Binary Testing:** Integration tests must validate the actual compiled binary in `dist/`. For network tests, this includes spawning the binary, ensuring it binds to UDP 500/4500/1701 and TCP 4500, and checking if the virtual TUN interface is successfully created.

## 🛑 Interactive Clarification Protocol (CRITICAL)
IPsec, L2TP, IKEv1, and IKEv2 ([RFC 4303](https://datatracker.ietf.org/doc/html/rfc4303), [RFC 2661](https://datatracker.ietf.org/doc/html/rfc2661), [RFC 2409](https://datatracker.ietf.org/doc/html/rfc2409), [RFC 7296](https://datatracker.ietf.org/doc/html/rfc7296), [RFC 3948](https://datatracker.ietf.org/doc/html/rfc3948), [RFC 4555](https://datatracker.ietf.org/doc/html/rfc4555), [RFC 8229](https://datatracker.ietf.org/doc/html/rfc8229), and the [LibreSWAN ipsec.conf.5 manual](https://libreswan.org/man/ipsec.conf.5.html)) are notoriously complex protocols. 
**DO NOT GUESS OR HALLUCINATE PROTOCOL LOGIC.** If you encounter an IPsec/ESP structure, PPP state machine requirement, or cryptographic derivation step (like PRF+) that is ambiguous or not fully understood, you **MUST** pause execution, state the ambiguity, and ask the human engineer for clarification before writing the code.