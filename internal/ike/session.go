package ike

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/dimaskiddo/swan-ng/internal/esp"
	"github.com/dimaskiddo/swan-ng/internal/log"
)

// SessionManager orchestrates all active IKEv1 and IKEv2 sessions.
// It bridges the IKE control plane with the ESP data plane.
type SessionManager struct {
	mu sync.RWMutex

	// v1Sessions maps the 16-byte SPI pair to an IKEv1 session.
	v1Sessions map[[16]byte]*IKEv1Session

	// v2Sessions maps the 16-byte SPI pair to an IKEv2 session.
	v2Sessions map[[16]byte]*IKEv2Session

	// identityMap maps a PeerID (string representation) to an active SPI pair.
	// Used to enforce the strict "Single Connection per Identity" rule.
	identityMap map[string][16]byte

	// assignedIPs tracks assigned virtual IPs (key: IP string, value: SPI pair).
	assignedIPs map[string][16]byte

	// espEngine provides access to the ESP data plane (SADatabase and SPD).
	espEngine *esp.Engine
}

// NewSessionManager creates a new IKE session manager.
func NewSessionManager(espEngine *esp.Engine) *SessionManager {
	return &SessionManager{
		v1Sessions:  make(map[[16]byte]*IKEv1Session),
		v2Sessions:  make(map[[16]byte]*IKEv2Session),
		identityMap: make(map[string][16]byte),
		assignedIPs: make(map[string][16]byte),
		espEngine:   espEngine,
	}
}

// ---- IKEv2 Session Management ----

// RegisterV2Session adds a new IKEv2 session to the manager.
// If an existing session for the same PeerID exists, it is evicted.
func (sm *SessionManager) RegisterV2Session(sess *IKEv2Session) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	spiPair := sess.SPIPair()
	peerIDStr := string(sess.PeerID)

	// Enforce Session Isolation (Single Connection per Identity).
	if existingSPI, exists := sm.identityMap[peerIDStr]; exists {
		log.Info("IKEv2 session eviction: identical PeerID reconnected",
			"peer_id", peerIDStr,
			"old_spi", fmt.Sprintf("%x", existingSPI[:8]),
			"new_spi", fmt.Sprintf("%x", spiPair[:8]),
		)
		sm.evictSessionLocked(existingSPI)
	}

	sm.v2Sessions[spiPair] = sess
	if len(sess.PeerID) > 0 {
		sm.identityMap[peerIDStr] = spiPair
	}

	log.Debug("IKEv2 session registered", "spi", fmt.Sprintf("%x", spiPair[:8]))
	return nil
}

// GetV2Session retrieves an IKEv2 session by its SPI pair.
func (sm *SessionManager) GetV2Session(spiPair [16]byte) *IKEv2Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.v2Sessions[spiPair]
}

// DeleteV2Session safely removes an IKEv2 session and its ESP SAs.
func (sm *SessionManager) DeleteV2Session(spiPair [16]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.evictSessionLocked(spiPair)
}

// ---- IKEv1 Session Management ----

// RegisterV1Session adds a new IKEv1 session.
func (sm *SessionManager) RegisterV1Session(sess *IKEv1Session) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	spiPair := sess.SPIPair()
	peerIDStr := string(sess.PeerID)

	if len(sess.PeerID) > 0 {
		if existingSPI, exists := sm.identityMap[peerIDStr]; exists {
			log.Info("IKEv1 session eviction: identical PeerID reconnected",
				"peer_id", peerIDStr,
				"old_spi", fmt.Sprintf("%x", existingSPI[:8]),
				"new_spi", fmt.Sprintf("%x", spiPair[:8]),
			)
			sm.evictSessionLocked(existingSPI)
		}
		sm.identityMap[peerIDStr] = spiPair
	}

	sm.v1Sessions[spiPair] = sess

	log.Debug("IKEv1 session registered", "spi", fmt.Sprintf("%x", spiPair[:8]))
	return nil
}

// GetV1Session retrieves an IKEv1 session by its SPI pair.
func (sm *SessionManager) GetV1Session(spiPair [16]byte) *IKEv1Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.v1Sessions[spiPair]
}

// DeleteV1Session safely removes an IKEv1 session and its ESP SAs.
func (sm *SessionManager) DeleteV1Session(spiPair [16]byte) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.evictSessionLocked(spiPair)
}

// ---- ESP Bridging & Isolation Logic ----

// evictSessionLocked handles the teardown of a session.
// It removes the session from maps and deletes associated ESP SAs.
// Must be called with sm.mu Lock held.
func (sm *SessionManager) evictSessionLocked(spiPair [16]byte) {
	var peerIDStr string
	var assignedIP net.IP

	// Try IKEv2.
	if sess, ok := sm.v2Sessions[spiPair]; ok {
		sess.mu.Lock()
		sess.State = StateV2Deleting
		peerIDStr = string(sess.PeerID)

		// Clean up ESP SAs.
		for _, child := range sess.ChildSAs {
			sm.removeESPChildSA(child.InSPI, child.OutSPI, nil) // dstIP usually peer addr or assigned IP
		}

		sess.mu.Unlock()
		delete(sm.v2Sessions, spiPair)
	}

	// Try IKEv1.
	if sess, ok := sm.v1Sessions[spiPair]; ok {
		sess.mu.Lock()
		sess.State = StateV1Deleting
		peerIDStr = string(sess.PeerID)

		// Remove ESP SAs.
		for _, child := range sess.ChildSAs {
			sm.removeESPChildSA(child.InSPI, child.OutSPI, nil)
		}

		sess.mu.Unlock()
		delete(sm.v1Sessions, spiPair)
	}

	// Clean identity map.
	if peerIDStr != "" {
		if mapped, exists := sm.identityMap[peerIDStr]; exists && mapped == spiPair {
			delete(sm.identityMap, peerIDStr)
		}
	}

	// Unbind assigned IP (simplified lookup).
	for ipStr, pair := range sm.assignedIPs {
		if pair == spiPair {
			delete(sm.assignedIPs, ipStr)
			assignedIP = net.ParseIP(ipStr)
			break
		}
	}

	if assignedIP != nil {
		sm.espEngine.RemoveOutboundSA(assignedIP)
	}
}

// InstallV2ChildSA injects an IKEv2 negotiated Child SA into the ESP engine.
func (sm *SessionManager) InstallV2ChildSA(sess *IKEv2Session, child *IKEv2ChildSA, assignedIP net.IP) error {
	if sm.espEngine == nil {
		return fmt.Errorf("ESP engine not configured")
	}

	// The espEngine uses uint32 for SPIs.
	inboundSPI := binary.BigEndian.Uint32(child.InSPI[:])
	outboundSPI := binary.BigEndian.Uint32(child.OutSPI[:])

	// Create Inbound ESP SA (decrypts traffic from peer).
	inSA, err := sm.buildESPSA(inboundSPI, child.EncrID, child.IntegID, child.PeerEncrKey, child.PeerIntegKey, sess.PeerAddr)
	if err != nil {
		return fmt.Errorf("building inbound SA: %w", err)
	}

	sm.espEngine.AddInboundSA(inSA)

	// Create Outbound ESP SA (encrypts traffic to peer).
	outSA, err := sm.buildESPSA(outboundSPI, child.EncrID, child.IntegID, child.EncrKey, child.IntegKey, sess.PeerAddr)
	if err != nil {
		sm.espEngine.RemoveInboundSA(inboundSPI)
		return fmt.Errorf("building outbound SA: %w", err)
	}

	// Map the outbound SA in the SPD if we have an assigned IP.
	// Outbound traffic bound FOR the client (dstIP = assignedIP) goes to outSA.
	if assignedIP != nil {
		sm.espEngine.AddOutboundSA(assignedIP, outSA)

		sm.mu.Lock()
		sm.assignedIPs[assignedIP.String()] = sess.SPIPair()
		sm.mu.Unlock()
	}

	log.Info("IKEv2 Child SA installed into ESP engine",
		"spi_in", fmt.Sprintf("0x%08X", inboundSPI),
		"spi_out", fmt.Sprintf("0x%08X", outboundSPI),
		"dst_ip", assignedIP,
	)

	return nil
}

// InstallV1ChildSA injects an IKEv1 negotiated Child SA into the ESP engine.
func (sm *SessionManager) InstallV1ChildSA(sess *IKEv1Session, child *IKEv1ChildSA, assignedIP net.IP) error {
	if sm.espEngine == nil {
		return fmt.Errorf("ESP engine not configured")
	}

	inboundSPI := binary.BigEndian.Uint32(child.InSPI[:])
	outboundSPI := binary.BigEndian.Uint32(child.OutSPI[:])

	// For IKEv1, our inbound SA uses our encryption keys (received traffic),
	// outbound SA uses peer's encryption keys (sent traffic).
	// NOTE: Wait, IKEv1 sets "EncrKey" as our key (inbound), "PeerEncrKey" as peer key (outbound).
	inSA, err := sm.buildESPSA(inboundSPI, child.EncrID, child.IntegID, child.EncrKey, child.IntegKey, sess.PeerAddr)
	if err != nil {
		return fmt.Errorf("building inbound SA: %w", err)
	}

	sm.espEngine.AddInboundSA(inSA)

	outSA, err := sm.buildESPSA(outboundSPI, child.EncrID, child.IntegID, child.PeerEncrKey, child.PeerIntegKey, sess.PeerAddr)
	if err != nil {
		sm.espEngine.RemoveInboundSA(inboundSPI)
		return fmt.Errorf("building outbound SA: %w", err)
	}

	if assignedIP != nil {
		sm.espEngine.AddOutboundSA(assignedIP, outSA)

		sm.mu.Lock()
		sm.assignedIPs[assignedIP.String()] = sess.SPIPair()
		sm.mu.Unlock()
	}

	log.Info("IKEv1 Child SA installed into ESP engine",
		"spi_in", fmt.Sprintf("0x%08X", inboundSPI),
		"spi_out", fmt.Sprintf("0x%08X", outboundSPI),
		"dst_ip", assignedIP,
	)

	return nil
}

// buildESPSA creates an esp.SecurityAssociation from negotiated parameters.
func (sm *SessionManager) buildESPSA(spi uint32, encrID, _ uint16, encrKey, _ []byte, peerAddr *net.UDPAddr) (*esp.SecurityAssociation, error) {
	// Map IKE encryption IDs to ESP constants.
	var espEncr esp.CipherSuite
	switch encrID {

	case 20: // EncrAES_GCM_16
		if len(encrKey) == 20 {
			espEncr = esp.AES128GCM
		} else if len(encrKey) == 36 {
			espEncr = esp.AES256GCM
		} else {
			return nil, fmt.Errorf("invalid AES_GCM key length %d", len(encrKey))
		}

	case 28: // EncrCHACHA20_POLY1305
		if len(encrKey) == 36 {
			espEncr = esp.CHACHA20POLY1305
		} else {
			return nil, fmt.Errorf("invalid CHACHA20_POLY1305 key length %d", len(encrKey))
		}

	default:
		return nil, fmt.Errorf("unsupported ESP encryption algorithm %d (AEAD required)", encrID)
	}

	saltLen := esp.AEADSaltSize(espEncr)
	keyLen := len(encrKey) - saltLen
	if keyLen <= 0 {
		return nil, fmt.Errorf("encryption key too short for salt")
	}

	key := encrKey[:keyLen]
	salt := encrKey[keyLen:]

	// Note: We ignore integID and integKey because the ESP engine operates strictly in AEAD mode.
	// Anti-replay window is created internally by NewSecurityAssociation when withReplay is true.

	return esp.NewSecurityAssociation(spi, espEncr, key, salt, peerAddr, true)
}

func (sm *SessionManager) removeESPChildSA(inSPI, _ [4]byte, assignedIP net.IP) {
	if sm.espEngine != nil {
		sm.espEngine.RemoveInboundSA(binary.BigEndian.Uint32(inSPI[:]))
		if assignedIP != nil {
			sm.espEngine.RemoveOutboundSA(assignedIP)
		}
	}
}
