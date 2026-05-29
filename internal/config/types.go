package config

// Config is the root configuration structure for SWAN-NG.
// It maps standard LibreSWAN/StrongSWAN configuration into a modern YAML format.
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Logging LoggingConfig `yaml:"logging"`
	TUN     TUNConfig     `yaml:"tun"`
	IPSec   IPSecConfig   `yaml:"ipsec"`
	IKEv2   IKEv2Config   `yaml:"ikev2"`
	L2TP    L2TPConfig    `yaml:"l2tp"`
}

// ServerConfig holds server identity and listen address settings.
type ServerConfig struct {
	// Hostname is the server's FQDN used for certificate generation and IKEv2 identity.
	Hostname string `yaml:"hostname"`
	// Listen is the address to bind UDP/TCP listeners on (e.g., "0.0.0.0").
	Listen string `yaml:"listen"`
}

// TUNConfig holds virtual TUN interface settings.
type TUNConfig struct {
	// DeviceName is the name prefix for the TUN interface.
	// On Linux: "swan0", "swan1", etc. On macOS: auto-assigned utun.
	// On Windows: adapter name shown in Network Connections.
	// Default: "swan0".
	DeviceName string `yaml:"device_name"`
	// MTU is the Maximum Transmission Unit for the TUN interface.
	// Default: 1280 (safe for ESP overhead + IPv6 minimum).
	MTU int `yaml:"mtu"`
}

// LoggingConfig controls structured logging behavior and file rotation.
type LoggingConfig struct {
	// Level is the minimum log level: "debug", "info", "warn", "error".
	Level string `yaml:"level"`
	// Output determines where logs go: "stdout" or "file".
	Output string `yaml:"output"`
	// File is the path to the log file (e.g. "/var/log/swan-ng.log"). If empty, logs to stderr only.
	File string `yaml:"file"`
	// MaxSize is the maximum size in megabytes of the log file before it gets rotated.
	MaxSize int `yaml:"max_size"`
	// MaxBackups is the maximum number of old log files to retain.
	MaxBackups int `yaml:"max_backups"`
	// MaxAge is the maximum number of days to retain old log files.
	MaxAge int `yaml:"max_age"`
	// Compress determines if the rotated log files should be compressed using gzip.
	Compress bool `yaml:"compress"`
}

// IPSecConfig holds the top-level IPsec configuration.
// Named connections are loaded from inline `connections:` map AND/OR
// from separate YAML files under `ipsec.d/` directory (similar to profile.d/).
type IPSecConfig struct {
	// Connections is a map of named IPsec connection definitions.
	// Each key is the connection name (e.g., "l2tp-responder", "office-s2s").
	// Mirrors LibreSWAN "conn <name>" blocks.
	Connections map[string]*ConnectionConfig `yaml:"connections"`

	// ConnectionDir is a list of paths to directories or files containing
	// additional connection definitions (e.g., "ipsec.d/" or "ipsec.d/office-s2s.yaml").
	// Paths are resolved relative to the config file directory.
	ConnectionDir []string `yaml:"connection_dir"`

	// HotReload enables live reloading of ipsec.d/ connection files
	// and config.yaml ipsec section changes without daemon restart.
	// Default: false.
	HotReload bool `yaml:"hot_reload"`
}

// ConnectionConfig maps ALL standard LibreSWAN ipsec.conf(5) connection parameters
// into a strongly typed Go struct. Each field corresponds to a documented parameter
// at https://libreswan.org/man/ipsec.conf.5.html
//
// Fields are optional unless validated otherwise by the loader.
// Zero values mean "not set" — the loader applies LibreSWAN-compatible defaults.
type ConnectionConfig struct {
	// --- Connection Identity & Endpoints ---

	// Left is the local endpoint identifier.
	// Values: IP address, DNS hostname, "%defaultroute", "%any".
	// (required per ipsec.conf.5)
	Left string `yaml:"left"`

	// LeftID is the local IKE identity. Defaults to Left.
	// Can be IP, FQDN, or @literal.
	LeftID string `yaml:"leftid"`

	// LeftSubnet is the traffic selector behind the left participant.
	// Comma-separated list: "10.0.1.0/24" or "10.0.1.0/24,10.0.2.0/24".
	// When omitted, assumed to be Left only (host-to-host).
	LeftSubnet string `yaml:"leftsubnet"`

	// LeftSourceIP is the IP address for this host to use when transmitting
	// to the other side. Used for subnet-subnet connections.
	LeftSourceIP string `yaml:"leftsourceip"`

	// LeftNextHop is the next-hop gateway IP for the left participant.
	// Default: "%direct" (meaning right). "%defaultroute" uses default route gateway.
	LeftNextHop string `yaml:"leftnexthop"`

	// LeftProtoPort is the allowed protocols/ports over connection (Port Selectors).
	// Format: "protocol/port" e.g., "17/1701" for L2TP.
	LeftProtoPort string `yaml:"leftprotoport"`

	// LeftAddressPool is the IP pool for IKEv2 server to assign to clients.
	// Format: "192.168.1.100-192.168.1.200" (range) or "2001:db8::/97" (CIDR).
	LeftAddressPool string `yaml:"leftaddresspool"`

	// LeftCert is the certificate nickname for this endpoint (NSS/X.509).
	LeftCert string `yaml:"leftcert"`

	// LeftAuth is for asymmetric authentication (IKEv2 only).
	// Values: "rsasig", "rsa", "rsa-sha2", "ecdsa", "secret", "null", "eaponly".
	LeftAuth string `yaml:"leftauth"`

	// LeftSendCert controls when to send X.509 certificates.
	// Values: "always", "sendifasked", "never". Default: "sendifasked".
	LeftSendCert string `yaml:"leftsendcert"`

	// LeftModeCfgServer marks left as a Mode Config server (IKEv2 CP).
	LeftModeCfgServer string `yaml:"leftmodecfgserver"`

	// LeftModeCfgClient marks left as a Mode Config client.
	LeftModeCfgClient string `yaml:"leftmodecfgclient"`

	// Right is the remote endpoint identifier.
	// Values: IP address, DNS hostname, "%any" (accept any client).
	// (required per ipsec.conf.5)
	Right string `yaml:"right"`

	// RightID is the remote IKE identity. Defaults to Right.
	RightID string `yaml:"rightid"`

	// RightSubnet is the traffic selector behind the right participant.
	RightSubnet string `yaml:"rightsubnet"`

	// RightSourceIP is the source IP for the right participant.
	RightSourceIP string `yaml:"rightsourceip"`

	// RightNextHop is the next-hop gateway IP for the right participant.
	RightNextHop string `yaml:"rightnexthop"`

	// RightProtoPort is the allowed protocols/ports for the right side.
	RightProtoPort string `yaml:"rightprotoport"`

	// RightAddressPool is the IP pool for the right side.
	RightAddressPool string `yaml:"rightaddresspool"`

	// RightCert is the certificate nickname for the right endpoint.
	RightCert string `yaml:"rightcert"`

	// RightAuth is for asymmetric authentication on the right side (IKEv2 only).
	RightAuth string `yaml:"rightauth"`

	// RightSendCert controls when the right side sends certificates.
	RightSendCert string `yaml:"rightsendcert"`

	// RightModeCfgServer marks right as a Mode Config server.
	RightModeCfgServer string `yaml:"rightmodecfgserver"`

	// RightModeCfgClient marks right as a Mode Config client.
	RightModeCfgClient string `yaml:"rightmodecfgclient"`

	// --- Authentication ---

	// AuthBy specifies how peers authenticate each other.
	// Values: "secret" (PSK), "rsasig", "ecdsa", "rsa-sha2", "never", "null".
	// PSK cannot be combined with other methods.
	AuthBy string `yaml:"authby"`

	// PSK is the Pre-Shared Key for this connection.
	// Per AGENTS.md PSK Isolation Rule: PSK MUST live inside each named connection block.
	PSK string `yaml:"psk"`

	// --- Connection Type & Behavior ---

	// Type is the connection type.
	// Values: "tunnel" (default), "transport", "passthrough", "drop", "reject".
	Type string `yaml:"type"`

	// Auto controls what happens at daemon startup.
	// Values: "add", "start", "route", "ondemand", "ignore" (default), "keep".
	Auto string `yaml:"auto"`

	// KeyExchange selects the IKE version.
	// Values: "ikev2" (default), "ikev1".
	KeyExchange string `yaml:"keyexchange"`

	// --- Encryption & Algorithms ---

	// IKE specifies Phase 1 (IKE SA) cipher suites.
	// Format: "cipher-hash-modpgroup,cipher-hash-modpgroup,...".
	// If empty, builtin defaults are used.
	IKE string `yaml:"ike"`

	// ESP specifies Phase 2 (Child SA / ESP) cipher suites.
	// Replaces the legacy "phase2alg" parameter.
	// Format: "cipher-hash,cipher-hash,...".
	ESP string `yaml:"esp"`

	// Phase2Alg is a legacy alias for ESP. If both are set, ESP takes precedence.
	Phase2Alg string `yaml:"phase2alg"`

	// Phase2 sets the type of SA produced.
	// Values: "esp" (default, encryption), "ah" (authentication only).
	Phase2 string `yaml:"phase2"`

	// --- Encapsulation & NAT Traversal ---

	// Encapsulation controls NAT-T UDP encapsulation.
	// Values: "auto" (default), "yes" (force), "no" (disable).
	Encapsulation string `yaml:"encapsulation"`

	// NATKeepalive controls whether NAT-T keepalive packets are sent.
	// Values: "yes" (default), "no".
	NATKeepalive string `yaml:"nat-keepalive"`

	// EnableTCP enables IKE/ESP over TCP per RFC 8229.
	// Values: "no" (default), "yes" (TCP only), "fallback" (UDP first, then TCP).
	EnableTCP string `yaml:"enable-tcp"`

	// TCPRemotePort is the remote TCP port for IKE-over-TCP. Default: 4500.
	TCPRemotePort int `yaml:"tcp-remoteport"`

	// --- Key Lifetime & Rekeying ---

	// IKELifetime is the IKE SA lifetime (e.g., "8h"). Default: "8h". Max: "24h".
	IKELifetime string `yaml:"ikelifetime"`

	// SALifetime is the child/IPsec SA lifetime (e.g., "8h"). Default: "8h". Max: "24h".
	SALifetime string `yaml:"salifetime"`

	// Rekey controls whether SAs are rekeyed before expiry.
	// Values: "yes" (default), "no".
	Rekey string `yaml:"rekey"`

	// RekeyMargin is how long before expiry to begin rekeying. Default: "9m".
	RekeyMargin string `yaml:"rekeymargin"`

	// RekeyFuzz is random percentage added to RekeyMargin. Default: "100%".
	RekeyFuzz string `yaml:"rekeyfuzz"`

	// KeyingTries is the number of SA negotiation retries (0 = unlimited).
	KeyingTries int `yaml:"keyingtries"`

	// --- Perfect Forward Secrecy ---

	// PFS enables Perfect Forward Secrecy for child SA rekeying.
	// Values: "yes" (default), "no".
	PFS string `yaml:"pfs"`

	// --- Dead Peer Detection ---

	// DPDDelay is the interval in seconds between DPD liveness checks. 0 = disabled.
	DPDDelay int `yaml:"dpddelay"`

	// DPDTimeout is the DPD timeout in seconds before declaring peer dead (IKEv1 only).
	DPDTimeout int `yaml:"dpdtimeout"`

	// DPDAction is the action on DPD timeout: "clear", "hold", "restart".
	DPDAction string `yaml:"dpdaction"`

	// --- MOBIKE ---

	// MOBIKE enables RFC 4555 endpoint migration for mobile clients.
	// Values: "no" (default), "yes".
	MOBIKE string `yaml:"mobike"`

	// --- Fragmentation ---

	// Fragmentation controls IKE fragmentation (RFC 7383).
	// Values: "yes" (default), "no", "force" (IKEv1 only).
	Fragmentation string `yaml:"fragmentation"`

	// --- Replay Protection ---

	// ReplayWindow is the anti-replay window size in packets. Default: 128. 0 = disabled.
	ReplayWindow int `yaml:"replay-window"`

	// ESN controls Extended Sequence Numbers.
	// Values: "either" (default), "yes", "no".
	ESN string `yaml:"esn"`

	// --- Retransmission ---

	// RetransmitTimeout is how long a single IKE exchange may take before aborting. Default: "60s".
	RetransmitTimeout string `yaml:"retransmit-timeout"`

	// RetransmitInterval is the initial retransmit interval in milliseconds. Default: 500.
	RetransmitInterval int `yaml:"retransmit-interval"`

	// --- Compression ---

	// Compress enables IPComp compression before encryption.
	// Values: "no" (default), "yes".
	Compress string `yaml:"compress"`

	// --- Compatibility ---

	// SHA2TruncBug enables compatibility with draft SHA2 truncation (96 bits vs 128 bits).
	// Values: "no" (default), "yes".
	SHA2TruncBug string `yaml:"sha2-truncbug"`

	// Narrowing enables IKEv2 traffic selector narrowing (RFC 5996 §2.9).
	// Values: "no" (default), "yes".
	Narrowing string `yaml:"narrowing"`

	// InitialContact controls sending INITIAL_CONTACT payload.
	// Values: "yes" (default), "no".
	InitialContact string `yaml:"initial-contact"`

	// --- ModeCfg / CP (Configuration Payloads) ---

	// ModeCfgDNS is a comma/space separated list of DNS server IPs to push to clients.
	ModeCfgDNS string `yaml:"modecfgdns"`

	// ModeCfgDomains is a comma/space separated list of internal domain names.
	ModeCfgDomains string `yaml:"modecfgdomains"`

	// --- Address Family ---

	// HostAddrFamily is the address family of the hosts: "ipv4", "ipv6".
	// Default: auto-detect from IP addresses.
	HostAddrFamily string `yaml:"hostaddrfamily"`

	// ClientAddrFamily is the address family of the clients: "ipv4", "ipv6".
	// Default: auto-detect from network addresses.
	ClientAddrFamily string `yaml:"clientaddrfamily"`
}

// IPAMConfig defines the internal IP address pool for client assignment.
type IPAMConfig struct {
	// Range specifies the IP pool in "start - end" format (e.g., "10.0.0.10 - 10.0.0.250").
	Range string `yaml:"range"`
	// DNS is the list of DNS servers assigned to clients via IKEv2 Configuration Payloads.
	DNS []string `yaml:"dns"`
}

// IKEv2Config holds IKEv2-specific settings.
type IKEv2Config struct {
	// Enabled toggles the IKEv2 engine for end-user VPN clients.
	Enabled bool `yaml:"enabled"`
	// IPAM holds the address pool configuration for IKEv2 clients.
	IPAM IPAMConfig `yaml:"ipam"`
	// Profile is a list of paths to IKEv2 user profile YAML files,
	// resolved relative to the config file directory.
	Profile []string `yaml:"profile"`
	// HotReload enables live reloading of IKEv2 profile changes
	// in profile.d/ without daemon restart.
	// Default: false.
	HotReload bool `yaml:"hot_reload"`
}

// L2TPConfig holds L2TP over IPsec specific settings.
type L2TPConfig struct {
	// Enabled toggles the L2TP over IPsec engine for infrastructure appliances.
	Enabled bool `yaml:"enabled"`
	// IPAM holds the dedicated L2TP address pool configuration.
	// Separate from the global/IKEv2 IPAM pool to prevent address conflicts.
	IPAM L2TPIPAMConfig `yaml:"ipam"`
	// Profile is a list of paths to L2TP user profile YAML files,
	// resolved relative to the config file directory.
	Profile []string `yaml:"profile"`
	// HotReload enables live reloading of L2TP profile changes
	// in profile.d/ without daemon restart.
	// Default: false.
	HotReload bool `yaml:"hot_reload"`
}

// L2TPIPAMConfig holds the dedicated L2TP IP address pool settings.
type L2TPIPAMConfig struct {
	// Gateway is the server-side PPP link IP address.
	// This is the IP assigned to the SWAN-NG server on the PPP interface.
	// Default: "192.168.42.1".
	Gateway string `yaml:"gateway"`
	// Range is the client IP address assignment range.
	// Format: "startIP - endIP" (e.g., "192.168.42.2 - 192.168.42.254").
	// Default: "192.168.42.2 - 192.168.42.254".
	Range string `yaml:"range"`
	// DNS is the list of DNS servers to assign to L2TP clients via IPCP.
	// Default: ["1.1.1.1", "1.0.0.1"] (Cloudflare).
	DNS []string `yaml:"dns"`
}
