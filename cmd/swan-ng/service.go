package main

import (
	"fmt"

	"github.com/kardianos/service"
	"github.com/spf13/cobra"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// serviceCmd is the parent command for OS service management.
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage SWAN-NG as an OS service (systemd/launchd/Windows)",
	Long: `Install or uninstall SWAN-NG as a system service.
Supports systemd (Linux), launchd (macOS), and Windows Services
via automatic detection of the host operating system.`,
}

// svcConfig defines the service configuration for kardianos/service.
var svcConfig = &service.Config{
	Name:        "swan-ng",
	DisplayName: "SWAN-NG VPN",
	Description: "SWAN Next-Generation IPsec VPN Daemon (IKEv2/L2TP/IKEv1)",
}

// serviceProgram implements the service.Interface for kardianos/service.
type serviceProgram struct{}

func (p *serviceProgram) Start(s service.Service) error {
	log.Info("service starting")
	return nil
}

func (p *serviceProgram) Stop(s service.Service) error {
	log.Info("service stopping")
	return nil
}

// serviceInstallCmd registers SWAN-NG as a system service.
var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install SWAN-NG as a system service",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return loadConfig()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Build service arguments with config path if provided.
		svcArgs := []string{"daemon"}
		if cfgPath != "" {
			svcArgs = append(svcArgs, "--config", cfgPath)
		}
		svcConfig.Arguments = svcArgs

		prg := &serviceProgram{}
		s, err := service.New(prg, svcConfig)
		if err != nil {
			return fmt.Errorf("creating service: %w", err)
		}

		if err := s.Install(); err != nil {
			return fmt.Errorf("installing service: %w", err)
		}

		log.Info("service installed successfully",
			"name", svcConfig.Name,
			"args", svcArgs,
		)

		fmt.Printf("Service %q installed successfully.\n", svcConfig.Name)
		return nil
	},
}

// serviceUninstallCmd removes SWAN-NG from the system services.
var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall SWAN-NG system service",
	RunE: func(cmd *cobra.Command, args []string) error {
		prg := &serviceProgram{}
		s, err := service.New(prg, svcConfig)
		if err != nil {
			return fmt.Errorf("creating service: %w", err)
		}

		if err := s.Uninstall(); err != nil {
			return fmt.Errorf("uninstalling service: %w", err)
		}

		log.Info("service uninstalled successfully",
			"name", svcConfig.Name,
		)

		fmt.Printf("Service %q uninstalled successfully.\n", svcConfig.Name)
		return nil
	},
}

func init() {
	serviceCmd.AddCommand(serviceInstallCmd)
	serviceCmd.AddCommand(serviceUninstallCmd)
	rootCmd.AddCommand(serviceCmd)
}
