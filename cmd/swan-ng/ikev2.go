package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/dimaskiddo/swan-ng/internal/certman"
	"github.com/dimaskiddo/swan-ng/internal/log"
)

// ikev2Cmd is the parent command for IKEv2 user management operations.
var ikev2Cmd = &cobra.Command{
	Use:   "ikev2",
	Short: "IKEv2 user certificate management",
	Long: `Manage IKEv2 VPN user certificates and profiles.
Target audience: end-user clients (mobile phones, Windows laptops, macOS) using certificate authentication.
Generates X.509 client certificates and exports .p12, .mobileconfig, and .sswan profiles.`,
}

// ikev2AddUserCmd creates a new IKEv2 user with auto-generated certificates.
var ikev2AddUserCmd = &cobra.Command{
	Use:   "add-user <username>",
	Short: "Create a new IKEv2 user with auto-generated certificates",
	Long: `Create certificates and profiles for a new IKEv2 VPN client.
Generates an X.509 client certificate and private key, then exports
client configuration profiles:
  - .p12 (PKCS#12 for Windows/Linux)
  - .mobileconfig (Apple iOS/macOS)
  - .sswan (Android strongSwan)

Enforces single-connection-per-identity: duplicate sessions are automatically evicted.`,
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

		log.Info("creating IKEv2 user",
			"username", username,
			"hostname", hostname,
		)

		// Resolve certs directory relative to config file.
		cfgDir := filepath.Dir(resolvedConfigPath)
		certsDir := filepath.Join(cfgDir, "certs")

		// Step 1: Initialize CA (auto-generate if first run).
		caCert, caKey, err := certman.InitCA(certsDir)
		if err != nil {
			return fmt.Errorf("initializing CA: %w", err)
		}

		// Step 2: Initialize server cert (auto-generate if first run).
		_, _, err = certman.InitServerCert(certsDir, hostname, caCert, caKey)
		if err != nil {
			return fmt.Errorf("initializing server cert: %w", err)
		}

		// Step 3: Prompt for certificate validity period.
		validityMonths := promptCertValidity()

		// Step 4: Generate client certificate.
		clientCertPath, clientKeyPath, err := certman.GenerateClientCert(certsDir, username, validityMonths, caCert, caKey)
		if err != nil {
			return fmt.Errorf("generating client cert: %w", err)
		}

		// Step 5: Export profiles.
		profileDir := filepath.Join(cfgDir, "profile.d")
		if err := os.MkdirAll(profileDir, 0755); err != nil {
			return fmt.Errorf("creating profile directory: %w", err)
		}

		caCertPath := filepath.Join(certsDir, "ca.crt")

		// Generate a random password for the P12 bundle.
		p12Password := username

		// Export .p12
		p12Path := filepath.Join(profileDir, fmt.Sprintf("ikev2-%s.p12", username))
		if err := certman.ExportP12(clientCertPath, clientKeyPath, caCertPath, p12Path, p12Password); err != nil {
			return fmt.Errorf("exporting .p12: %w", err)
		}

		// Export .mobileconfig
		mobileconfigPath := filepath.Join(profileDir, fmt.Sprintf("ikev2-%s.mobileconfig", username))
		if err := certman.ExportMobileconfig(username, hostname, caCertPath, p12Path, p12Password, mobileconfigPath); err != nil {
			return fmt.Errorf("exporting .mobileconfig: %w", err)
		}

		// Export .sswan
		sswanPath := filepath.Join(profileDir, fmt.Sprintf("ikev2-%s.sswan", username))
		if err := certman.ExportSSwan(username, hostname, caCertPath, p12Path, sswanPath); err != nil {
			return fmt.Errorf("exporting .sswan: %w", err)
		}

		// Step 6: Create user profile YAML.
		profilePath := filepath.Join(profileDir, fmt.Sprintf("ikev2-%s.yaml", username))
		if err := writeIKEv2Profile(profilePath, username, validityMonths, clientCertPath, clientKeyPath); err != nil {
			return fmt.Errorf("writing user profile: %w", err)
		}

		fmt.Println()
		fmt.Println("=== IKEv2 User Created Successfully ===")
		fmt.Printf("Username       : %s\n", username)
		fmt.Printf("Certificate    : %s\n", clientCertPath)
		fmt.Printf("Private Key    : %s\n", clientKeyPath)
		fmt.Printf("Validity       : %d months\n", validityMonths)
		fmt.Printf("P12 Bundle     : %s (password: %s)\n", p12Path, p12Password)
		fmt.Printf("Apple Profile  : %s\n", mobileconfigPath)
		fmt.Printf("Android Profile: %s\n", sswanPath)
		fmt.Printf("User Profile   : %s\n", profilePath)
		fmt.Println("========================================")

		return nil
	},
}

// promptCertValidity asks the administrator for the certificate validity period.
// Defaults to 120 months (10 years) if no input is given.
func promptCertValidity() int {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Certificate validity in months [120]: ")

	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" {
		return 120
	}

	months, err := strconv.Atoi(input)
	if err != nil || months <= 0 {
		log.Warn("invalid validity input, using default", "input", input)
		return 120
	}

	return months
}

// ikev2ProfileData represents the YAML structure for an IKEv2 user profile.
type ikev2ProfileData struct {
	Username       string `yaml:"username"`
	Certificate    string `yaml:"certificate"`
	Key            string `yaml:"key"`
	ValidityMonths int    `yaml:"validity_months"`
}

// writeIKEv2Profile creates the user profile YAML file in profile.d/.
func writeIKEv2Profile(path, username string, validityMonths int, certPath, keyPath string) error {
	profile := ikev2ProfileData{
		Username:       username,
		Certificate:    certPath,
		Key:            keyPath,
		ValidityMonths: validityMonths,
	}

	data, err := yaml.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshaling profile: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

func init() {
	ikev2Cmd.AddCommand(ikev2AddUserCmd)
	rootCmd.AddCommand(ikev2Cmd)
}
