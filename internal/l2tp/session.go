package l2tp

import (
	"net"
	"sync"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// Session states per RFC 2661 §7.4.2 (LNS incoming call).
const (
	SessionIdle        byte = 0
	SessionWaitConnect byte = 1
	SessionEstablished byte = 2
	SessionClosed      byte = 3
)

// PPP negotiation phases within an established session.
const (
	PPPPhaseLCP  byte = 0 // LCP negotiation in progress
	PPPPhaseCHAP byte = 1 // CHAP authentication in progress
	PPPPhaseIPCP byte = 2 // IPCP negotiation in progress
	PPPPhaseData byte = 3 // Fully established, forwarding IP data
)

// Session represents an L2TPv2 session within a tunnel.
// Each session corresponds to a single PPP stream between the LAC and this LNS.
type Session struct {
	mu sync.Mutex

	// state is the session state machine state.
	state byte

	// localSessionID is our assigned session ID.
	localSessionID uint16
	// remoteSessionID is the peer's assigned session ID.
	remoteSessionID uint16

	// tunnel is the parent tunnel.
	tunnel *Tunnel

	// PPP handlers.
	lcpHandler  *LCPHandler
	chapHandler *CHAPHandler
	ipcpHandler *IPCPHandler

	// pppPhase tracks which PPP negotiation phase we are in.
	pppPhase byte

	// assignedIP is the IP address assigned to the peer from IPAM.
	assignedIP net.IP
	// username stores the authenticated username.
	username string

	// lcpConfigSent tracks if we sent our initial LCP Configure-Request.
	lcpConfigSent bool
}

// newSession creates a new session in the WaitConnect state.
func newSession(localID, remoteID uint16, tunnel *Tunnel) *Session {
	return &Session{
		state:           SessionWaitConnect,
		localSessionID:  localID,
		remoteSessionID: remoteID,
		tunnel:          tunnel,
		pppPhase:        PPPPhaseLCP,
	}
}

// LocalSessionID returns this session's local ID.
func (s *Session) LocalSessionID() uint16 {
	return s.localSessionID
}

// RemoteSessionID returns the peer's session ID.
func (s *Session) RemoteSessionID() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.remoteSessionID
}

// State returns the current session state.
func (s *Session) State() byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Username returns the authenticated username.
func (s *Session) Username() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.username
}

// AssignedIP returns the IP assigned to the peer.
func (s *Session) AssignedIP() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.assignedIP
}

// handleICCN processes Incoming-Call-Connected, transitioning to established.
// Starts PPP negotiation.
func (s *Session) handleICCN(avps []AVP) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionWaitConnect {
		log.Warn("l2tp: ICCN in unexpected session state",
			"session", s.localSessionID,
			"state", s.state,
		)
		return errInvalidState
	}

	s.state = SessionEstablished

	log.Info("l2tp: session established",
		"local_sid", s.localSessionID,
		"remote_sid", s.remoteSessionID,
		"tunnel", s.tunnel.localTunnelID,
	)

	return nil
}

// InitPPP initializes PPP handlers and starts LCP negotiation.
// Must be called after session reaches established state.
// hostname: server hostname for CHAP challenge.
// userDB: user database for CHAP authentication.
// assignedIP, gatewayIP: IP addresses from IPAM pool.
// dns1, dns2: DNS servers to assign.
func (s *Session) InitPPP(hostname string, userDB UserDatabase, assignedIP, gatewayIP, dns1, dns2 net.IP) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.lcpHandler = NewLCPHandler()
	s.chapHandler = NewCHAPHandler(hostname, userDB)
	s.ipcpHandler = NewIPCPHandler(assignedIP, gatewayIP, dns1, dns2)
	s.assignedIP = assignedIP
	s.pppPhase = PPPPhaseLCP

	// Build and send our LCP Configure-Request.
	lcpReq := s.lcpHandler.BuildConfigureRequest()
	s.lcpConfigSent = true
	return SerializePPPFrame(PPPProtoLCP, lcpReq)
}

// HandleData processes an L2TP data message payload (PPP frame).
// Returns zero or more PPP response frames to send back.
func (s *Session) HandleData(payload []byte) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != SessionEstablished {
		return nil
	}

	// Parse PPP frame.
	pppFrame, err := ParsePPPFrame(payload)
	if err != nil {
		log.Debug("l2tp: invalid PPP frame",
			"session", s.localSessionID,
			"error", err.Error(),
		)
		return nil
	}

	switch pppFrame.Protocol {
	case PPPProtoLCP:
		return s.handleLCP(pppFrame.Payload)
	case PPPProtoCHAP:
		return s.handleCHAP(pppFrame.Payload)
	case PPPProtoIPCP:
		return s.handleIPCP(pppFrame.Payload)
	case PPPProtoIPv4:
		return s.handleIPv4(pppFrame.Payload)
	case PPPProtoPAP:
		// Reject PAP — we require CHAP only.
		log.Debug("l2tp: rejecting PAP", "session", s.localSessionID)
		if s.lcpHandler != nil {
			rej := s.lcpHandler.BuildProtocolReject(PPPProtoPAP, pppFrame.Payload)
			return [][]byte{SerializePPPFrame(PPPProtoLCP, rej)}
		}
		return nil
	case PPPProtoCCP:
		// Reject CCP — no compression support.
		log.Debug("l2tp: rejecting CCP", "session", s.localSessionID)
		if s.lcpHandler != nil {
			rej := s.lcpHandler.BuildProtocolReject(PPPProtoCCP, pppFrame.Payload)
			return [][]byte{SerializePPPFrame(PPPProtoLCP, rej)}
		}
		return nil
	case PPPProtoIPv6CP:
		// Reject IPv6CP — IPv4 only.
		log.Debug("l2tp: rejecting IPv6CP", "session", s.localSessionID)
		if s.lcpHandler != nil {
			rej := s.lcpHandler.BuildProtocolReject(PPPProtoIPv6CP, pppFrame.Payload)
			return [][]byte{SerializePPPFrame(PPPProtoLCP, rej)}
		}
		return nil
	default:
		log.Debug("l2tp: unknown PPP protocol",
			"session", s.localSessionID,
			"protocol", pppFrame.Protocol,
		)
		if s.lcpHandler != nil {
			rej := s.lcpHandler.BuildProtocolReject(pppFrame.Protocol, pppFrame.Payload)
			return [][]byte{SerializePPPFrame(PPPProtoLCP, rej)}
		}
		return nil
	}
}

// handleLCP processes LCP packets and manages state transitions.
func (s *Session) handleLCP(data []byte) [][]byte {
	if s.lcpHandler == nil {
		return nil
	}

	resp := s.lcpHandler.Handle(data)

	var responses [][]byte
	if resp != nil {
		responses = append(responses, SerializePPPFrame(PPPProtoLCP, resp))
	}

	// Check if LCP is now opened → transition to CHAP phase.
	if s.lcpHandler.IsOpened() && s.pppPhase == PPPPhaseLCP {
		s.pppPhase = PPPPhaseCHAP

		log.Debug("l2tp: LCP opened, starting CHAP",
			"session", s.localSessionID,
		)

		// Send CHAP Challenge.
		if s.chapHandler != nil {
			challenge := s.chapHandler.BuildChallenge()
			responses = append(responses, SerializePPPFrame(PPPProtoCHAP, challenge))
		}
	}

	return responses
}

// handleCHAP processes CHAP packets and manages state transitions.
func (s *Session) handleCHAP(data []byte) [][]byte {
	if s.chapHandler == nil || s.pppPhase != PPPPhaseCHAP {
		log.Debug("l2tp: CHAP received in wrong phase",
			"session", s.localSessionID,
			"phase", s.pppPhase,
		)
		return nil
	}

	resp := s.chapHandler.Handle(data)

	var responses [][]byte
	if resp != nil {
		responses = append(responses, SerializePPPFrame(PPPProtoCHAP, resp))
	}

	// Check if CHAP authentication succeeded → transition to IPCP.
	if s.chapHandler.IsAuthenticated() {
		s.username = s.chapHandler.Username()
		s.pppPhase = PPPPhaseIPCP

		log.Info("l2tp: CHAP authenticated, starting IPCP",
			"session", s.localSessionID,
			"username", s.username,
		)

		// Send our IPCP Configure-Request.
		if s.ipcpHandler != nil {
			ipcpReq := s.ipcpHandler.BuildConfigureRequest()
			responses = append(responses, SerializePPPFrame(PPPProtoIPCP, ipcpReq))
		}
	}

	return responses
}

// handleIPCP processes IPCP packets and manages state transitions.
func (s *Session) handleIPCP(data []byte) [][]byte {
	if s.ipcpHandler == nil || s.pppPhase != PPPPhaseIPCP {
		log.Debug("l2tp: IPCP received in wrong phase",
			"session", s.localSessionID,
			"phase", s.pppPhase,
		)
		return nil
	}

	resp := s.ipcpHandler.Handle(data)

	var responses [][]byte
	if resp != nil {
		responses = append(responses, SerializePPPFrame(PPPProtoIPCP, resp))
	}

	// Check if IPCP is fully negotiated → data phase.
	if s.ipcpHandler.IsOpened() && s.pppPhase == PPPPhaseIPCP {
		s.pppPhase = PPPPhaseData

		log.Info("l2tp: PPP fully established",
			"session", s.localSessionID,
			"username", s.username,
			"peer_ip", s.assignedIP,
			"gateway", s.ipcpHandler.GatewayIP(),
		)
	}

	return responses
}

// handleIPv4 processes IPv4 data packets from the peer.
// In the data phase, these are forwarded to the TUN device.
func (s *Session) handleIPv4(data []byte) [][]byte {
	if s.pppPhase != PPPPhaseData {
		log.Debug("l2tp: IPv4 data before PPP established",
			"session", s.localSessionID,
		)
		return nil
	}

	// Forward to TUN device via server.
	if s.tunnel != nil && s.tunnel.server != nil {
		s.tunnel.server.forwardToTUN(data)
	}

	return nil
}

// SendData sends a PPP data frame to the peer via the L2TP data channel.
func (s *Session) SendData(pppFrame []byte) {
	s.mu.Lock()
	if s.state != SessionEstablished {
		s.mu.Unlock()
		return
	}
	remoteTID := s.tunnel.remoteTunnelID
	remoteSID := s.remoteSessionID
	s.mu.Unlock()

	// Build L2TP data header + PPP frame.
	hdr := BuildDataHeader(remoteTID, remoteSID)
	pkt := make([]byte, len(hdr)+len(pppFrame))
	copy(pkt, hdr)
	copy(pkt[len(hdr):], pppFrame)

	s.tunnel.sendFunc(pkt, s.tunnel.peerAddr)
}

// close cleans up session resources.
func (s *Session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == SessionClosed {
		return
	}

	s.state = SessionClosed

	// Release IPAM address.
	if s.assignedIP != nil && s.tunnel != nil && s.tunnel.server != nil {
		s.tunnel.server.releaseIP(s.assignedIP)
	}

	log.Info("l2tp: session closed",
		"session", s.localSessionID,
		"username", s.username,
		"ip", s.assignedIP,
	)
}
