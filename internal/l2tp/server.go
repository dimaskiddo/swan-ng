package l2tp

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/ipam"
	"github.com/dimaskiddo/swan-ng/internal/log"
)

// tunnelKey uniquely identifies a tunnel by peer address + remote tunnel ID.
type tunnelKey struct {
	addr     string
	tunnelID uint16
}

// TUNWriter is the interface for writing packets to a TUN device.
type TUNWriter interface {
	WritePacket(buf []byte, n int) error
}

// ResponseSender is the interface for sending L2TP responses back to the peer.
// In production, this sends through the ESP encrypt → UDP path.
type ResponseSender interface {
	SendL2TPResponse(data []byte, peerAddr *net.UDPAddr) error
}

// Server is the central L2TP server managing all tunnels and sessions.
// It acts as an LNS (L2TP Network Server) accepting incoming tunnel
// and session requests from LAC clients.
type Server struct {
	mu sync.RWMutex

	// tunnels maps tunnelKey → *Tunnel.
	tunnels map[tunnelKey]*Tunnel

	// tunnelsByLocalID maps localTunnelID → *Tunnel for fast data-path lookup.
	tunnelsByLocalID map[uint16]*Tunnel

	// pool is the dedicated L2TP IPAM pool.
	pool *ipam.Pool

	// userDB provides user credentials for CHAP authentication.
	userDB *ProfileUserDB

	// hostname is the server hostname for L2TP AVPs and CHAP.
	hostname string

	// gatewayIP is the server-side PPP link IP.
	gatewayIP net.IP

	// dns1, dns2 are the DNS servers to assign to clients.
	dns1 net.IP
	dns2 net.IP

	// sender sends L2TP response packets back to the peer.
	sender ResponseSender

	// tunWriter writes decapsulated IP packets to the TUN device.
	tunWriter TUNWriter

	// nextTunnelID is an atomic counter for tunnel ID allocation.
	nextTunnelID atomic.Uint32

	// ctx is the server's root context.
	ctx context.Context
}

// ServerConfig holds configuration for creating a new L2TP server.
type ServerConfig struct {
	// Hostname is the server hostname used in L2TP and CHAP.
	Hostname string
	// GatewayIP is the server-side PPP interface IP (e.g., 192.168.42.1).
	GatewayIP net.IP
	// DNS1 is the primary DNS server to assign (default: 1.1.1.1).
	DNS1 net.IP
	// DNS2 is the secondary DNS server to assign (default: 1.0.0.1).
	DNS2 net.IP
	// Pool is the dedicated L2TP IPAM pool.
	Pool *ipam.Pool
	// UserDB is the profile-based user database.
	UserDB *ProfileUserDB
	// Sender sends response packets back to peers.
	Sender ResponseSender
	// TUNWriter writes decapsulated IP packets to the TUN device.
	TUNWriter TUNWriter
}

// NewServer creates a new L2TP server with the given configuration.
func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		tunnels:          make(map[tunnelKey]*Tunnel),
		tunnelsByLocalID: make(map[uint16]*Tunnel),
		pool:             cfg.Pool,
		userDB:           cfg.UserDB,
		hostname:         cfg.Hostname,
		gatewayIP:        cfg.GatewayIP,
		dns1:             cfg.DNS1,
		dns2:             cfg.DNS2,
		sender:           cfg.Sender,
		tunWriter:        cfg.TUNWriter,
	}
	s.nextTunnelID.Store(1)
	return s
}

// Start begins the L2TP server's background operations.
func (s *Server) Start(ctx context.Context) {
	s.ctx = ctx
	log.Info("l2tp: server started",
		"hostname", s.hostname,
		"gateway", s.gatewayIP,
		"users", s.userDB.UserCount(),
	)
}

// HandlePacket is the main entry point for incoming L2TP packets.
// Called from the ESP decrypt path when an inner UDP:1701 packet is detected.
// data contains the raw L2TP packet (after UDP header has been stripped).
func (s *Server) HandlePacket(data []byte, peerAddr *net.UDPAddr) {
	// Parse L2TP header.
	hdr, payload, err := ParseHeader(data)
	if err != nil {
		log.Debug("l2tp: failed to parse header",
			"from", peerAddr,
			"error", err.Error(),
		)
		return
	}

	// Route based on message type (control vs data) and tunnel ID.
	if hdr.IsControl {
		s.handleControlMessage(hdr, payload, peerAddr)
	} else {
		s.handleDataMessage(hdr, payload, peerAddr)
	}
}

// handleControlMessage processes an L2TP control message.
func (s *Server) handleControlMessage(hdr *Header, payload []byte, peerAddr *net.UDPAddr) {
	// TunnelID=0 in a control message → new tunnel request (SCCRQ).
	if hdr.TunnelID == 0 {
		s.handleNewTunnel(hdr, payload, peerAddr)
		return
	}

	// Lookup tunnel by our local tunnel ID.
	s.mu.RLock()
	tunnel, ok := s.tunnelsByLocalID[hdr.TunnelID]
	s.mu.RUnlock()

	if !ok {
		log.Debug("l2tp: control for unknown tunnel",
			"tunnel_id", hdr.TunnelID,
			"from", peerAddr,
		)
		return
	}

	// Update activity timestamp.
	tunnel.mu.Lock()
	tunnel.lastActivity = time.Now()
	tunnel.mu.Unlock()

	// Process sequence numbers for reliable delivery.
	isZLB := len(payload) == 0
	inOrder := tunnel.control.Receive(hdr.Ns, hdr.Nr, isZLB)

	// Always send ZLB ACK for received control messages (including duplicates).
	tunnel.control.SendZLB()

	if !inOrder {
		return
	}

	// Parse AVPs from payload.
	avps, err := ParseAVPs(payload)
	if err != nil {
		log.Debug("l2tp: failed to parse AVPs",
			"tunnel", hdr.TunnelID,
			"error", err.Error(),
		)
		return
	}

	msgType := GetMessageType(avps)
	s.routeControlMessage(tunnel, hdr, msgType, avps)
}

// handleNewTunnel processes SCCRQ for a new tunnel (TunnelID=0).
func (s *Server) handleNewTunnel(hdr *Header, payload []byte, peerAddr *net.UDPAddr) {
	avps, err := ParseAVPs(payload)
	if err != nil {
		log.Debug("l2tp: failed to parse SCCRQ AVPs", "error", err.Error())
		return
	}

	msgType := GetMessageType(avps)
	if msgType != MsgSCCRQ {
		log.Debug("l2tp: expected SCCRQ but got", "type", msgType)
		return
	}

	// Allocate local tunnel ID.
	localTID := uint16(s.nextTunnelID.Add(1))
	if localTID == 0 {
		localTID = uint16(s.nextTunnelID.Add(1))
	}

	// Create tunnel.
	tunnel := newTunnel(localTID, peerAddr, func(data []byte, addr *net.UDPAddr) {
		if s.sender != nil {
			if err := s.sender.SendL2TPResponse(data, addr); err != nil {
				log.Debug("l2tp: failed to send response",
					"error", err.Error(),
					"peer", addr,
				)
			}
		}
	}, s)

	// Process Ns/Nr for the initial SCCRQ.
	tunnel.control.Receive(hdr.Ns, hdr.Nr, false)

	// Handle SCCRQ.
	if err := tunnel.HandleSCCRQ(avps, s.hostname); err != nil {
		log.Warn("l2tp: SCCRQ handling failed",
			"error", err.Error(),
			"peer", peerAddr,
		)
		return
	}

	// Register tunnel.
	remoteTID, _ := GetAVPUint16(avps, AVPAssignedTunnelID)
	key := tunnelKey{addr: peerAddr.String(), tunnelID: remoteTID}

	s.mu.Lock()
	s.tunnels[key] = tunnel
	s.tunnelsByLocalID[localTID] = tunnel
	s.mu.Unlock()

	// Start tunnel background goroutine.
	if s.ctx != nil {
		go tunnel.Run(s.ctx)
	}

	// Send ZLB ACK for the SCCRQ.
	tunnel.control.SendZLB()
}

// routeControlMessage dispatches a control message to the appropriate handler.
func (s *Server) routeControlMessage(tunnel *Tunnel, hdr *Header, msgType uint16, avps []AVP) {
	switch msgType {
	case MsgSCCCN:
		if err := tunnel.HandleSCCCN(avps); err != nil {
			log.Warn("l2tp: SCCCN handling failed",
				"tunnel", tunnel.localTunnelID,
				"error", err.Error(),
			)
		}

	case MsgICRQ:
		sess, err := tunnel.HandleICRQ(avps)
		if err != nil {
			log.Warn("l2tp: ICRQ handling failed",
				"tunnel", tunnel.localTunnelID,
				"error", err.Error(),
			)
			return
		}
		// ACK the ICRQ.
		tunnel.control.SendZLB()
		_ = sess // Session created and ICRP sent.

	case MsgICCN:
		// ICCN is for a specific session.
		if err := tunnel.HandleICCN(hdr.SessionID, avps); err != nil {
			log.Warn("l2tp: ICCN handling failed",
				"tunnel", tunnel.localTunnelID,
				"session", hdr.SessionID,
				"error", err.Error(),
			)
			return
		}

		// Session is now established — initialize PPP.
		sess := tunnel.GetSession(hdr.SessionID)
		if sess != nil {
			assignedIP := s.allocateIP()
			if assignedIP == nil {
				log.Warn("l2tp: IPAM pool exhausted",
					"session", sess.localSessionID,
				)
				tunnel.SendCDN(sess.localSessionID, 4)
				return
			}

			lcpReq := sess.InitPPP(s.hostname, s.userDB, assignedIP, s.gatewayIP, s.dns1, s.dns2)
			if lcpReq != nil {
				sess.SendData(lcpReq)
			}
		}

	case MsgHello:
		tunnel.HandleHello()

	case MsgCDN:
		tunnel.HandleCDN(avps)
		if tunnel.SessionCount() == 0 {
			log.Debug("l2tp: no sessions remaining, tunnel idle",
				"tunnel", tunnel.localTunnelID,
			)
		}

	case MsgStopCCN:
		tunnel.HandleStopCCN(avps)
		s.removeTunnel(tunnel)

	default:
		log.Debug("l2tp: unhandled control message type",
			"type", msgType,
			"tunnel", tunnel.localTunnelID,
		)
	}
}

// handleDataMessage processes an L2TP data message (PPP frame).
func (s *Server) handleDataMessage(hdr *Header, payload []byte, peerAddr *net.UDPAddr) {
	// Lookup tunnel by local tunnel ID.
	s.mu.RLock()
	tunnel, ok := s.tunnelsByLocalID[hdr.TunnelID]
	s.mu.RUnlock()

	if !ok {
		log.Debug("l2tp: data for unknown tunnel",
			"tunnel_id", hdr.TunnelID,
			"from", peerAddr,
		)
		return
	}

	// Update activity.
	tunnel.mu.Lock()
	tunnel.lastActivity = time.Now()
	tunnel.mu.Unlock()

	// Find session by session ID.
	sess := tunnel.GetSession(hdr.SessionID)
	if sess == nil {
		log.Debug("l2tp: data for unknown session",
			"tunnel", hdr.TunnelID,
			"session", hdr.SessionID,
		)
		return
	}

	// Process PPP frame and get responses.
	responses := sess.HandleData(payload)
	for _, resp := range responses {
		sess.SendData(resp)
	}
}

// allocateIP gets an IP address from the L2TP IPAM pool.
func (s *Server) allocateIP() net.IP {
	if s.pool == nil {
		return nil
	}
	ip, err := s.pool.Allocate()
	if err != nil {
		log.Debug("l2tp: IP allocation failed", "error", err.Error())
		return nil
	}
	return ip
}

// releaseIP returns an IP address to the L2TP IPAM pool.
func (s *Server) releaseIP(ip net.IP) {
	if s.pool == nil || ip == nil {
		return
	}
	if err := s.pool.Release(ip); err != nil {
		log.Debug("l2tp: IP release failed", "error", err.Error(), "ip", ip)
	}
}

// forwardToTUN writes a decapsulated IP packet to the TUN device.
func (s *Server) forwardToTUN(data []byte) {
	if s.tunWriter == nil || len(data) == 0 {
		return
	}
	if err := s.tunWriter.WritePacket(data, len(data)); err != nil {
		log.Debug("l2tp: TUN write failed", "error", err.Error())
	}
}

// removeTunnel removes a dead tunnel from the server's maps.
func (s *Server) removeTunnel(tunnel *Tunnel) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.tunnelsByLocalID, tunnel.localTunnelID)

	for key, t := range s.tunnels {
		if t == tunnel {
			delete(s.tunnels, key)
			break
		}
	}

	log.Debug("l2tp: tunnel removed",
		"tunnel", tunnel.localTunnelID,
		"remaining", len(s.tunnels),
	)
}

// TunnelCount returns the number of active tunnels.
func (s *Server) TunnelCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tunnels)
}

// Close shuts down the L2TP server and all tunnels.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, tunnel := range s.tunnels {
		tunnel.Close()
	}

	s.tunnels = make(map[tunnelKey]*Tunnel)
	s.tunnelsByLocalID = make(map[uint16]*Tunnel)

	log.Info("l2tp: server stopped")
}
