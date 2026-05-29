package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// ResolveConfigPath determines the config file path.
// If flagPath is provided (via --config CLI flag), it takes full precedence.
// Otherwise, resolves config.yaml relative to the directory where the
// swan-ng executable actually resides (not the user's CWD).
func ResolveConfigPath(flagPath string) (string, error) {
	if flagPath != "" {
		abs, err := filepath.Abs(flagPath)
		if err != nil {
			return "", fmt.Errorf("resolving config flag path: %w", err)
		}

		log.Debug("config path from --config flag", "path", abs)
		return abs, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolving executable path: %w", err)
	}

	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", fmt.Errorf("resolving executable symlinks: %w", err)
	}

	dir := filepath.Dir(exe)
	cfgPath := filepath.Join(dir, "config.yaml")

	log.Debug("config path from executable directory", "path", cfgPath)
	return cfgPath, nil
}

// Load reads and parses a YAML config file into a Config struct.
// After parsing, it loads external connection files from ipsec.d/,
// applies defaults for any missing values, and validates.
func Load(path string) (*Config, error) {
	log.Info("loading configuration", "path", path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	cfgDir := filepath.Dir(path)

	// Initialize connections map if nil.
	if cfg.IPSec.Connections == nil {
		cfg.IPSec.Connections = make(map[string]*ConnectionConfig)
	}

	// Load external connection files from ipsec.d/ directories.
	if err := loadConnectionDirs(&cfg, cfgDir); err != nil {
		return nil, fmt.Errorf("loading ipsec connection directories: %w", err)
	}

	// Apply defaults and validate.
	if err := applyDefaultsAndValidate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Resolve relative profile paths.
	cfg.IKEv2.Profile = resolveProfilePaths(cfgDir, cfg.IKEv2.Profile)
	cfg.L2TP.Profile = resolveProfilePaths(cfgDir, cfg.L2TP.Profile)

	log.Info("configuration loaded",
		"hostname", cfg.Server.Hostname,
		"listen", cfg.Server.Listen,
		"connections", len(cfg.IPSec.Connections),
		"ikev2_enabled", cfg.IKEv2.Enabled,
		"ikev2_ipam_range", cfg.IKEv2.IPAM.Range,
		"ikev2_dns_servers", cfg.IKEv2.IPAM.DNS,
		"l2tp_enabled", cfg.L2TP.Enabled,
		"l2tp_ipam_gateway", cfg.L2TP.IPAM.Gateway,
		"l2tp_ipam_range", cfg.L2TP.IPAM.Range,
		"l2tp_dns_servers", cfg.L2TP.IPAM.DNS,
		"ipsec_hot_reload", cfg.IPSec.HotReload,
		"ikev2_hot_reload", cfg.IKEv2.HotReload,
		"l2tp_hot_reload", cfg.L2TP.HotReload,
	)

	return &cfg, nil
}

// loadConnectionDirs loads IPsec connection definitions from external
// YAML files referenced in ipsec.connection_dir (similar to profile.d/).
//
// Each YAML file in the directory defines a single connection:
//
//	# ipsec.d/office-s2s.yaml
//	left: "<host_ip>"
//	right: "<office_ip>"
//	authby: "secret"
//	psk: "<psk>"
//
// The filename (without .yaml extension) becomes the connection name.
func loadConnectionDirs(cfg *Config, cfgDir string) error {
	// Default: look for ipsec.d/ in the config directory if no explicit dirs specified.
	dirs := cfg.IPSec.ConnectionDir
	if len(dirs) == 0 {
		defaultDir := filepath.Join(cfgDir, "ipsec.d")
		if info, err := os.Stat(defaultDir); err == nil && info.IsDir() {
			dirs = []string{"ipsec.d"}
		}
	}

	for _, dir := range dirs {
		absDir := dir
		if !filepath.IsAbs(absDir) {
			absDir = filepath.Join(cfgDir, absDir)
		}

		info, err := os.Stat(absDir)
		if err != nil {
			if os.IsNotExist(err) {
				log.Debug("ipsec connection directory not found, skipping",
					"path", absDir,
				)

				continue
			}

			return fmt.Errorf("accessing %q: %w", absDir, err)
		}

		if !info.IsDir() {
			// Single file — load as connection.
			if err := loadConnectionFile(cfg, absDir); err != nil {
				return err
			}

			continue
		}

		// Directory — load all .yaml files.
		entries, err := os.ReadDir(absDir)
		if err != nil {
			return fmt.Errorf("reading directory %q: %w", absDir, err)
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
				continue
			}

			filePath := filepath.Join(absDir, name)
			if err := loadConnectionFile(cfg, filePath); err != nil {
				return err
			}
		}
	}

	return nil
}

// loadConnectionFile loads a single connection YAML file.
// The connection name is derived from the filename (without extension).
func loadConnectionFile(cfg *Config, filePath string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("reading connection file %q: %w", filePath, err)
	}

	var conn ConnectionConfig
	if err := yaml.Unmarshal(data, &conn); err != nil {
		return fmt.Errorf("parsing connection file %q: %w", filePath, err)
	}

	// Derive connection name from filename.
	base := filepath.Base(filePath)
	name := strings.TrimSuffix(base, filepath.Ext(base))

	// Inline connections take precedence — don't overwrite.
	if _, exists := cfg.IPSec.Connections[name]; exists {
		log.Warn("connection already defined inline, skipping file",
			"name", name,
			"file", filePath,
		)

		return nil
	}

	cfg.IPSec.Connections[name] = &conn

	log.Info("loaded ipsec connection from file",
		"name", name,
		"file", filePath,
	)

	return nil
}

// applyDefaultsAndValidate fills in missing config values with sensible defaults
// per the LibreSWAN ipsec.conf.5 manual (https://libreswan.org/man/ipsec.conf.5.html)
// and validates that truly required parameters are defined.
func applyDefaultsAndValidate(cfg *Config) error {
	// --- Server defaults ---
	if cfg.Server.Hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("server.hostname is not set and unable to detect operating system hostname: %w", err)
		}
		cfg.Server.Hostname = h

		log.Info("server.hostname is not set, using operating system hostname", "hostname", h)
	}
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "0.0.0.0"
	}

	// --- Logging defaults ---
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Output == "" {
		cfg.Logging.Output = "stdout"
	}
	if cfg.Logging.MaxSize == 0 {
		cfg.Logging.MaxSize = 10
	}
	if cfg.Logging.MaxBackups == 0 {
		cfg.Logging.MaxBackups = 5
	}
	if cfg.Logging.MaxAge == 0 {
		cfg.Logging.MaxAge = 7
	}

	// --- IPsec connection defaults ---
	if len(cfg.IPSec.Connections) == 0 {
		return fmt.Errorf("ipsec.connections: at least one named connection must be defined")
	}

	for name, conn := range cfg.IPSec.Connections {
		if err := applyConnectionDefaults(name, conn); err != nil {
			return fmt.Errorf("ipsec.connections.%s: %w", name, err)
		}
	}

	// --- IKEv2 IPAM defaults ---
	if cfg.IKEv2.IPAM.Range == "" {
		cfg.IKEv2.IPAM.Range = "10.0.0.10 - 10.0.0.250"
	}
	if len(cfg.IKEv2.IPAM.DNS) == 0 {
		cfg.IKEv2.IPAM.DNS = []string{"1.1.1.1", "1.0.0.1"}
	}

	// --- L2TP IPAM defaults ---
	if cfg.L2TP.IPAM.Gateway == "" {
		cfg.L2TP.IPAM.Gateway = "192.168.42.1"
	}
	if cfg.L2TP.IPAM.Range == "" {
		cfg.L2TP.IPAM.Range = "192.168.42.2 - 192.168.42.254"
	}
	if len(cfg.L2TP.IPAM.DNS) == 0 {
		cfg.L2TP.IPAM.DNS = []string{"1.1.1.1", "1.0.0.1"}
	}

	return nil
}

// applyConnectionDefaults applies LibreSWAN ipsec.conf.5 default values
// and validates required fields for a single named connection.
func applyConnectionDefaults(name string, conn *ConnectionConfig) error {
	// --- Required fields ---
	if conn.Left == "" {
		return fmt.Errorf("left is required (e.g. \"%%defaultroute\" or a specific IP)")
	}
	if conn.Right == "" {
		return fmt.Errorf("right is required (e.g. \"%%any\" or a specific IP)")
	}
	if conn.AuthBy == "" {
		return fmt.Errorf("authby is required (e.g. \"secret\", \"rsasig\", \"never\")")
	}

	// PSK required when authby=secret.
	if conn.AuthBy == "secret" && conn.PSK == "" {
		return fmt.Errorf("psk is required when authby=secret (PSK Isolation Rule)")
	}

	// --- Connection type defaults ---
	if conn.Type == "" {
		conn.Type = "tunnel"
	}
	if conn.Auto == "" {
		conn.Auto = "ignore"
	}

	// --- Key exchange default ---
	if conn.KeyExchange == "" {
		conn.KeyExchange = "ikev2"
	}

	// --- Encapsulation & NAT ---
	if conn.Encapsulation == "" {
		conn.Encapsulation = "auto"
	}
	if conn.NATKeepalive == "" {
		conn.NATKeepalive = "yes"
	}
	if conn.EnableTCP == "" {
		conn.EnableTCP = "no"
	}

	// --- Key lifetime defaults ---
	if conn.IKELifetime == "" {
		conn.IKELifetime = "8h"
	}
	if conn.SALifetime == "" {
		conn.SALifetime = "8h"
	}

	// --- Rekeying defaults ---
	if conn.Rekey == "" {
		conn.Rekey = "yes"
	}
	if conn.RekeyMargin == "" {
		conn.RekeyMargin = "9m"
	}
	if conn.RekeyFuzz == "" {
		conn.RekeyFuzz = "100%"
	}

	// --- PFS default ---
	if conn.PFS == "" {
		conn.PFS = "yes"
	}

	// --- DPD defaults ---
	if conn.DPDDelay > 0 && conn.DPDAction == "" {
		conn.DPDAction = "clear"
	}

	// --- MOBIKE default ---
	if conn.MOBIKE == "" {
		conn.MOBIKE = "no"
	}

	// --- Fragmentation default ---
	if conn.Fragmentation == "" {
		conn.Fragmentation = "yes"
	}

	// --- Replay window default ---
	// Note: 0 means explicitly disabled, -1 or unset means use default.
	// Since Go int zero-value is 0, we use a sentinel approach:
	// If not explicitly set in YAML, it stays 0 which we treat as "use default 128".
	// To explicitly disable, user sets replay-window: -1 in YAML.
	// This is a pragmatic choice for YAML compatibility.

	// --- ESN default ---
	if conn.ESN == "" {
		conn.ESN = "either"
	}

	// --- Retransmission default ---
	if conn.RetransmitTimeout == "" {
		conn.RetransmitTimeout = "60s"
	}
	if conn.RetransmitInterval == 0 {
		conn.RetransmitInterval = 500
	}

	// --- Compression default ---
	if conn.Compress == "" {
		conn.Compress = "no"
	}

	// --- Compatibility default ---
	if conn.SHA2TruncBug == "" {
		conn.SHA2TruncBug = "no"
	}
	if conn.Narrowing == "" {
		conn.Narrowing = "no"
	}
	if conn.InitialContact == "" {
		conn.InitialContact = "yes"
	}

	// --- Phase2 default ---
	if conn.Phase2 == "" {
		conn.Phase2 = "esp"
	}

	// Legacy: phase2alg -> esp migration.
	if conn.ESP == "" && conn.Phase2Alg != "" {
		conn.ESP = conn.Phase2Alg
	}

	log.Info("ipsec connection validated",
		"name", name,
		"left", conn.Left,
		"right", conn.Right,
		"authby", conn.AuthBy,
		"type", conn.Type,
		"auto", conn.Auto,
		"keyexchange", conn.KeyExchange,
	)

	return nil
}

// FindConnectionByAuthBy returns the first connection with the specified authby value.
// Used by l2tp add-user to find the PSK-authenticated connection.
// Returns connection name and config, or empty string and nil if not found.
func FindConnectionByAuthBy(cfg *Config, authBy string) (string, *ConnectionConfig) {
	for name, conn := range cfg.Connections() {
		if conn.AuthBy == authBy {
			return name, conn
		}
	}

	return "", nil
}

// Connections returns the IPsec connections map. Convenience accessor.
func (c *Config) Connections() map[string]*ConnectionConfig {
	if c.IPSec.Connections == nil {
		return make(map[string]*ConnectionConfig)
	}

	return c.IPSec.Connections
}

// resolveProfilePaths converts relative profile paths to absolute paths
// based on the config file's directory.
func resolveProfilePaths(cfgDir string, paths []string) []string {
	resolved := make([]string, 0, len(paths))
	for _, p := range paths {
		if filepath.IsAbs(p) {
			resolved = append(resolved, p)
			continue
		}

		resolved = append(resolved, filepath.Join(cfgDir, p))
	}

	return resolved
}
