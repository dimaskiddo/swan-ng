package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/swan-ng/internal/config"
	"github.com/dimaskiddo/swan-ng/internal/log"
)

var (
	cfgPath            string
	resolvedConfigPath string
	cfg                *config.Config
)

// rootCmd is the base command for swan-ng.
var rootCmd = &cobra.Command{
	Use:   "swan-ng",
	Short: "SWAN-NG — SWAN Next-Generation IPsec VPN (IKEv2/L2TP/IKEv1)",
	Long: `SWAN-NG is a modern rewrite of LibreSWAN/StrongSWAN providing
IKEv2, L2TP over IPsec, and user-space ESP packet routing in a secure,
memory-safe, and highly portable single binary.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgPath, "config", "",
		"path to config.yaml (default: resolved relative to executable)")
}

// loadConfig resolves and loads the configuration file.
// Called in PersistentPreRunE of commands that need config.
func loadConfig() error {
	resolvedPath, err := config.ResolveConfigPath(cfgPath)
	if err != nil {
		return fmt.Errorf("resolving config path: %w", err)
	}

	loaded, err := config.Load(resolvedPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	cfg = loaded
	resolvedConfigPath = resolvedPath

	// Reconfigure logger based on loaded config
	log.InitLogger(&log.Config{
		Level:      cfg.Logging.Level,
		Output:     cfg.Logging.Output,
		FilePath:   cfg.Logging.File,
		MaxSize:    cfg.Logging.MaxSize,
		MaxBackups: cfg.Logging.MaxBackups,
		MaxAge:     cfg.Logging.MaxAge,
		Compress:   cfg.Logging.Compress,
	})

	return nil
}

func main() {
	// Initialize structured logger with basic settings for pre-configuration logging.
	log.InitLogger(&log.Config{
		Level:  "info",
		Output: "stdout",
	})

	if err := rootCmd.Execute(); err != nil {
		log.Error("command failed", "error", err)
		os.Exit(1)
	}
}
