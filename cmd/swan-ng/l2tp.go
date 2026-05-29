package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/dimaskiddo/swan-ng/internal/certman"
	"github.com/dimaskiddo/swan-ng/internal/config"
	"github.com/dimaskiddo/swan-ng/internal/log"
)

var l2tpConnName string

// l2tpCmd is the parent command for L2TP over IPsec user management operations.
var l2tpCmd = &cobra.Command{
	Use:   "l2tp",
	Short: "L2TP over IPsec user management (PSK + PPP CHAP authentication)",
	Long: `Manage L2TP over IPsec VPN users with Pre-Shared Key and PPP CHAP authentication.
Target audience: infrastructure appliances (Like MikroTik or Palo Alto firewalls).
Supports multiple concurrent sessions per credential via distinct Tunnel/Session IDs.`,
}

// l2tpAddUserCmd creates a new L2TP user with PSK and PPP credentials.
var l2tpAddUserCmd = &cobra.Command{
	Use:   "add-user <username>",
	Short: "Create a new L2TP over IPsec user",
	Long: `Create a new L2TP over IPsec VPN user with multi-stage authentication:
  1. IPsec stage validated via Pre-Shared Key (PSK) from a named connection block
  2. L2TP/PPP stage authenticated via CHAP

Interactively prompts for the user's password with masked terminal input.
Generates a .txt distribution profile for network engineers.

The --connection flag selects which IPsec connection block to read the PSK from.
If omitted, the first connection with authby=secret is used.`,
	Args: cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return loadConfig()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		username := args[0]
		hostname := cfg.Server.Hostname

		if hostname == "" {
			return fmt.Errorf("server.hostname must be configured in config.yaml")
		}

		// Resolve the IPsec connection block for PSK lookup.
		connName, conn, err := resolveL2TPConnection(l2tpConnName)
		if err != nil {
			return err
		}

		psk := conn.PSK

		log.Info("creating L2TP user",
			"username", username,
			"hostname", hostname,
			"connection", connName,
		)

		// Step 1: Prompt for password with masked input.
		password, err := promptMaskedPassword("Enter L2TP password for user %q: ", username)
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
		if password == "" {
			return fmt.Errorf("password cannot be empty")
		}

		// Confirm password.
		confirm, err := promptMaskedPassword("Confirm L2TP password: ")
		if err != nil {
			return fmt.Errorf("reading password confirmation: %w", err)
		}
		if password != confirm {
			return fmt.Errorf("passwords do not match")
		}

		// Step 2: Create profile directory.
		cfgDir := filepath.Dir(resolvedConfigPath)
		profileDir := filepath.Join(cfgDir, "profile.d")
		if err := os.MkdirAll(profileDir, 0755); err != nil {
			return fmt.Errorf("creating profile directory: %w", err)
		}

		// Step 3: Create user profile YAML.
		profilePath := filepath.Join(profileDir, fmt.Sprintf("l2tp-%s.yaml", username))
		if err := writeL2TPProfile(profilePath, username, password); err != nil {
			return fmt.Errorf("writing user profile: %w", err)
		}

		// Step 4: Export .txt distribution profile.
		txtPath := filepath.Join(profileDir, fmt.Sprintf("l2tp-%s.txt", username))
		if err := certman.ExportL2TPProfile(username, password, hostname, psk, txtPath); err != nil {
			return fmt.Errorf("exporting L2TP profile: %w", err)
		}

		fmt.Println()
		fmt.Println("=== L2TP User Created Successfully ===")
		fmt.Printf("Username       : %s\n", username)
		fmt.Printf("Server         : %s\n", hostname)
		fmt.Printf("Connection     : %s\n", connName)
		fmt.Printf("User Profile   : %s\n", profilePath)
		fmt.Printf("Distribution   : %s\n", txtPath)
		fmt.Println("======================================")

		return nil
	},
}

// resolveL2TPConnection finds the IPsec connection block to use for L2TP PSK.
// If connName is specified, looks up that exact connection.
// If empty, finds the first connection with authby=secret.
func resolveL2TPConnection(connName string) (string, *config.ConnectionConfig, error) {
	if connName != "" {
		conn, exists := cfg.IPSec.Connections[connName]
		if !exists {
			return "", nil, fmt.Errorf("ipsec connection %q not found in config", connName)
		}

		if conn.PSK == "" {
			return "", nil, fmt.Errorf("ipsec connection %q has no PSK defined (authby=%s)", connName, conn.AuthBy)
		}

		return connName, conn, nil
	}

	// Auto-detect: find first connection with authby=secret.
	name, conn := config.FindConnectionByAuthBy(cfg, "secret")
	if conn == nil {
		return "", nil, fmt.Errorf("no ipsec connection with authby=secret found; use --connection to specify one")
	}

	return name, conn, nil
}

// promptMaskedPassword displays a prompt and reads password input with masked characters.
// Uses golang.org/x/term for secure terminal input.
func promptMaskedPassword(format string, args ...interface{}) (string, error) {
	fmt.Printf(format, args...)

	// Read password with masking from terminal.
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Newline after masked input.

	if err != nil {
		return "", fmt.Errorf("reading masked input: %w", err)
	}

	return string(passwordBytes), nil
}

// l2tpProfileData represents the YAML structure for an L2TP user profile.
type l2tpProfileData struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// writeL2TPProfile creates the user profile YAML file in profile.d/.
func writeL2TPProfile(path, username, password string) error {
	profile := l2tpProfileData{
		Username: username,
		Password: password,
	}

	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshaling profile: %w", err)
	}

	// Write with restricted permissions since it contains credentials.
	return os.WriteFile(path, data, 0600)
}

func init() {
	l2tpAddUserCmd.Flags().StringVar(&l2tpConnName, "connection", "",
		"IPsec connection name to read PSK from (default: first with authby=secret)")
	l2tpCmd.AddCommand(l2tpAddUserCmd)
	rootCmd.AddCommand(l2tpCmd)
}
