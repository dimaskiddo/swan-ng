package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/dimaskiddo/swan-ng/internal/esp"
	"github.com/dimaskiddo/swan-ng/internal/ike"
	"github.com/dimaskiddo/swan-ng/internal/ipam"
	"github.com/dimaskiddo/swan-ng/internal/l2tp"
	"github.com/dimaskiddo/swan-ng/internal/listener"
	"github.com/dimaskiddo/swan-ng/internal/log"
	"github.com/dimaskiddo/swan-ng/internal/tun"
)

// daemonCmd starts the SWAN-NG VPN daemon.
// It initializes the TUN device, UDP listeners, and ESP engine for
// user-space IPsec packet processing.
var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Start the SWAN-NG VPN daemon",
	Long: `Start the resident VPN daemon that manages TUN interfaces,
UDP/TCP listeners on ports 500/4500/1701, and handles
IKEv2/L2TP/ESP packet processing.`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return loadConfig()
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		log.Info("starting swan-ng daemon",
			"version", version,
			"commit", commit,
			"hostname", cfg.Server.Hostname,
			"listen", cfg.Server.Listen,
			"ipsec_connections", len(cfg.IPSec.Connections),
			"ikev2_enabled", cfg.IKEv2.Enabled,
			"l2tp_enabled", cfg.L2TP.Enabled,
		)

		// Create root context with signal-based cancellation.
		ctx, stop := signal.NotifyContext(context.Background(),
			os.Interrupt,
			syscall.SIGTERM,
		)
		defer stop()

		// Initialize buffer pool for zero-alloc packet processing.
		pool := esp.NewBufferPool(esp.MaxPacketSize)

		// Initialize SA database.
		saDB := esp.NewSADatabase()

		// Resolve TUN device name and MTU from config.
		tunName := cfg.TUN.DeviceName
		if tunName == "" {
			tunName = tun.DefaultDeviceName
		}

		tunMTU := cfg.TUN.MTU
		if tunMTU <= 0 {
			tunMTU = tun.DefaultMTU
		}

		// Check TUN availability before attempting creation.
		var tunDev *tun.Device

		tunAvailable, reason := tun.Available()
		if !tunAvailable {
			log.Warn("TUN device creation skipped",
				"reason", reason,
			)
		} else {
			var err error

			tunDev, err = tun.NewDevice(ctx, tunName, tunMTU)
			if err != nil {
				log.Error("TUN device creation failed, continuing without TUN",
					"error", err.Error(),
				)
			}
		}

		// Initialize listener manager.
		listenMgr := listener.NewManager(pool)
		listenAddr := cfg.Server.Listen
		if listenAddr == "" {
			listenAddr = "0.0.0.0"
		}

		// Create ESP engine.
		engineCfg := esp.EngineConfig{
			SADatabase: saDB,
			Pool:       pool,
			UDPSender:  listenMgr,
		}

		if tunDev != nil {
			engineCfg.TUNReader = tunDev
			engineCfg.TUNWriter = tunDev
		}

		espEngine, err := esp.NewEngine(engineCfg)
		if err != nil {
			return err
		}

		// --- IKE Server Initialization ---
		ikeSessionMgr := ike.NewSessionManager(espEngine)

		v1PSKFunc := func(peerAddr *net.UDPAddr) ([]byte, string, error) {
			for name, conn := range cfg.IPSec.Connections {
				if conn.AuthBy != "secret" || conn.KeyExchange != "ikev1" {
					continue
				}

				if conn.Right == "%any" || conn.Right == peerAddr.IP.String() {
					if conn.PSK != "" {
						return []byte(conn.PSK), name, nil
					}
				}
			}

			return nil, "", fmt.Errorf("no IKEv1 PSK found for %s", peerAddr.String())
		}
		ikev1Handler := ike.NewIKEv1Handler(v1PSKFunc, []byte("swan-ng"), ike.IDIPv4Addr)

		v2PSKFunc := func(peerAddr *net.UDPAddr, peerID []byte) ([]byte, string, error) {
			peerIDStr := string(peerID)
			for name, conn := range cfg.IPSec.Connections {
				if conn.AuthBy != "secret" || (conn.KeyExchange != "" && conn.KeyExchange != "ikev2") {
					continue
				}

				matchID := conn.Right
				if conn.RightID != "" {
					matchID = conn.RightID
				}

				if matchID == "%any" || matchID == peerIDStr || matchID == peerAddr.IP.String() {
					if conn.PSK != "" {
						return []byte(conn.PSK), name, nil
					}
				}
			}

			return nil, "", fmt.Errorf("no IKEv2 PSK found for %s (ID: %s)", peerAddr.String(), peerIDStr)
		}
		ikev2Handler := ike.NewIKEv2Handler(v2PSKFunc, []byte("swan-ng"), ike.IDIPv4Addr, ike.CookieModeAuto)

		ikeServer := ike.NewServer(ikeSessionMgr, ikev1Handler, ikev2Handler, listenMgr)

		// --- L2TP Server Initialization ---
		var l2tpServer *l2tp.Server
		if cfg.L2TP.Enabled {
			l2tpServer, err = initL2TPServer(ctx, espEngine, tunDev)
			if err != nil {
				log.Error("L2TP server initialization failed", "error", err.Error())
			}
		}

		// Bind UDP listeners.
		// Port 4500: NAT-T ESP + IKE demux.
		err = listenMgr.AddUDP(listenAddr, listener.PortNATT, "NAT-T/ESP",
			func(buf []byte, n int, remoteAddr *net.UDPAddr) {
				pktType, payload, err := esp.ClassifyNATT(buf[:n])
				if err != nil {
					log.Debug("NAT-T classification failed", "error", err, "peer", remoteAddr)
					return
				}
				if pktType == esp.PacketTypeIKE {
					ikeServer.HandlePacket(payload, len(payload), remoteAddr, true)
				} else {
					espEngine.HandleInboundESP(buf, n, remoteAddr)
				}
			},
		)
		if err != nil {
			log.Error("failed to bind UDP:4500", "error", err.Error())
		}

		// Port 500: IKE control.
		err = listenMgr.AddUDP(listenAddr, listener.PortIKE, "IKE",
			func(buf []byte, n int, remoteAddr *net.UDPAddr) {
				ikeServer.HandlePacket(buf, n, remoteAddr, false)
			},
		)
		if err != nil {
			log.Error("failed to bind UDP:500", "error", err.Error())
		}

		// Port 1701: L2TP direct UDP (non-ESP path, for testing/debugging).
		// In production, L2TP arrives via transport-mode ESP (port 4500) and
		// is routed internally by the ESP engine to the L2TP handler.
		err = listenMgr.AddUDP(listenAddr, listener.PortL2TP, "L2TP",
			func(buf []byte, n int, remoteAddr *net.UDPAddr) {
				if l2tpServer != nil {
					l2tpServer.HandlePacket(buf[:n], remoteAddr)
				} else {
					log.Debug("L2TP packet received but server disabled",
						"from", remoteAddr,
						"size", n,
					)
				}
			},
		)
		if err != nil {
			log.Error("failed to bind UDP:1701", "error", err.Error())
		}

		// Start ESP engine in background.
		go espEngine.Start(ctx)

		// Start listener manager in background.
		go listenMgr.Start(ctx)

		log.Info("daemon ready, waiting for connections",
			"udp_ports", []int{500, 4500, 1701},
			"tcp_ports", []int{4500},
		)

		if tunDev != nil {
			log.Info("TUN device active", "name", tunDev.Name(), "mtu", tunDev.MTU())
		}

		// Block until shutdown signal received.
		<-ctx.Done()

		log.Info("shutdown signal received, stopping daemon")

		// Graceful shutdown: close L2TP server.
		if l2tpServer != nil {
			l2tpServer.Close()
		}

		return nil
	},
}

// initL2TPServer creates and starts the L2TP server.
// It creates the dedicated IPAM pool, loads user profiles, and
// registers the server as an L2TP handler on the ESP engine.
func initL2TPServer(ctx context.Context, espEngine *esp.Engine, tunDev *tun.Device) (*l2tp.Server, error) {
	// Create dedicated L2TP IPAM pool.
	l2tpPool, err := ipam.NewPool(cfg.L2TP.IPAM.Range)
	if err != nil {
		return nil, fmt.Errorf("l2tp IPAM pool creation failed: %w", err)
	}

	log.Info("L2TP IPAM pool created",
		"gateway", cfg.L2TP.IPAM.Gateway,
		"range", cfg.L2TP.IPAM.Range,
		"available", l2tpPool.Available(),
	)

	// Load L2TP user profiles.
	userDB := l2tp.NewProfileUserDB()
	if len(cfg.L2TP.Profile) > 0 {
		// Resolve profile paths relative to config directory.
		var profilePaths []string
		for _, p := range cfg.L2TP.Profile {
			if !filepath.IsAbs(p) {
				p = filepath.Join(filepath.Dir(resolvedConfigPath), p)
			}
			profilePaths = append(profilePaths, p)
		}

		if err := userDB.LoadProfiles(profilePaths); err != nil {
			log.Warn("L2TP profile loading had errors", "error", err.Error())
		}
	}

	// Parse DNS servers.
	dns1 := net.ParseIP("1.1.1.1")
	dns2 := net.ParseIP("1.0.0.1")

	if len(cfg.L2TP.IPAM.DNS) >= 1 {
		if parsed := net.ParseIP(cfg.L2TP.IPAM.DNS[0]); parsed != nil {
			dns1 = parsed
		}
	}

	if len(cfg.L2TP.IPAM.DNS) >= 2 {
		if parsed := net.ParseIP(cfg.L2TP.IPAM.DNS[1]); parsed != nil {
			dns2 = parsed
		}
	}

	// Build L2TP server config.
	srvCfg := l2tp.ServerConfig{
		Hostname:  cfg.Server.Hostname,
		GatewayIP: net.ParseIP(cfg.L2TP.IPAM.Gateway),
		DNS1:      dns1,
		DNS2:      dns2,
		Pool:      l2tpPool,
		UserDB:    userDB,
	}

	// Set TUNWriter if TUN device is available.
	if tunDev != nil {
		srvCfg.TUNWriter = tunDev
	}

	l2tpServer := l2tp.NewServer(srvCfg)
	l2tpServer.Start(ctx)

	// Register L2TP server with ESP engine for transport-mode routing.
	espEngine.SetL2TPHandler(l2tpServer)

	log.Info("L2TP server initialized",
		"gateway", cfg.L2TP.IPAM.Gateway,
		"pool_size", l2tpPool.Size(),
		"users", userDB.UserCount(),
		"dns", cfg.L2TP.IPAM.DNS,
	)

	return l2tpServer, nil
}

func init() {
	rootCmd.AddCommand(daemonCmd)
}
