package l2tp

import (
	"context"
	"crypto/md5"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// Tunnel states per RFC 2661 §7.2.
const (
	TunnelIdle        byte = 0
	TunnelWaitCtlConn byte = 1
	TunnelEstablished byte = 2
	TunnelDead        byte = 3
)

// Tunnel represents an L2TPv2 tunnel (control connection) between
// this LNS and a remote LAC. A tunnel contains zero or more sessions.
type Tunnel struct {
	mu sync.Mutex

	// state is the tunnel state machine state.
	state byte

	// localTunnelID is our assigned tunnel ID.
	localTunnelID uint16
	// remoteTunnelID is the peer's assigned tunnel ID.
	remoteTunnelID uint16

	// peerAddr is the remote LAC's address.
	peerAddr *net.UDPAddr

	// peerHostname is the peer's Host Name from SCCRQ.
	peerHostname string

	// control manages reliable delivery for this tunnel.
	control *ControlChannel

	// sessions maps local session ID → Session.
	sessions map[uint16]*Session

	// nextSessionID is an atomic counter for session ID allocation.
	nextSessionID atomic.Uint32

	// helloInterval is the keepalive timer interval.
	helloInterval time.Duration
	// lastActivity tracks the last received message time for keepalive.
	lastActivity time.Time

	// cancel stops the tunnel's goroutines (keepalive, retransmit).
	cancel context.CancelFunc

	// sendFunc sends raw L2TP data to the peer.
	sendFunc func(data []byte, addr *net.UDPAddr)

	// server back-reference for session creation.
	server *Server
}

// newTunnel creates a new tunnel with the given local ID and peer address.
func newTunnel(localID uint16, peerAddr *net.UDPAddr, sendFunc func([]byte, *net.UDPAddr), srv *Server) *Tunnel {
	t := &Tunnel{
		state:         TunnelIdle,
		localTunnelID: localID,
		peerAddr:      peerAddr,
		sessions:      make(map[uint16]*Session),
		helloInterval: defaultHelloInterval,
		lastActivity:  time.Now(),
		sendFunc:      sendFunc,
		server:        srv,
	}
	t.nextSessionID.Store(1)

	// Create control channel with sender bound to this tunnel's peer.
	t.control = NewControlChannel(
		func(data []byte) {
			sendFunc(data, peerAddr)
		},
		func() {
			// Retransmit timeout — tunnel is dead.
			log.Warn("l2tp: tunnel retransmit timeout",
				"tunnel_id", localID,
				"peer", peerAddr,
			)
			t.mu.Lock()
			t.state = TunnelDead
			t.mu.Unlock()
		},
	)

	return t
}

// State returns the current tunnel state.
func (t *Tunnel) State() byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// LocalTunnelID returns this tunnel's local ID.
func (t *Tunnel) LocalTunnelID() uint16 {
	return t.localTunnelID
}

// RemoteTunnelID returns the peer's tunnel ID.
func (t *Tunnel) RemoteTunnelID() uint16 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remoteTunnelID
}

// PeerAddr returns the remote peer's address.
func (t *Tunnel) PeerAddr() *net.UDPAddr {
	return t.peerAddr
}

// HandleSCCRQ processes a Start-Control-Connection-Request.
// Validates the request, assigns our tunnel ID, sends SCCRP.
// Transitions: idle → wait-ctl-conn.
func (t *Tunnel) HandleSCCRQ(avps []AVP, hostname string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != TunnelIdle {
		log.Warn("l2tp: SCCRQ in non-idle state", "state", t.state)
		return errInvalidState
	}

	// Extract peer's assigned tunnel ID.
	remoteTID, ok := GetAVPUint16(avps, AVPAssignedTunnelID)
	if !ok || remoteTID == 0 {
		log.Warn("l2tp: SCCRQ missing Assigned Tunnel ID")
		return errMissingAVP
	}
	t.remoteTunnelID = remoteTID
	t.control.SetRemoteTunnelID(remoteTID)

	// Extract peer's receive window size.
	if rwSize, ok := GetAVPUint16(avps, AVPReceiveWindowSize); ok {
		t.control.SetPeerWindow(rwSize)
	}

	// Extract peer hostname.
	if hn, ok := GetAVPString(avps, AVPHostName); ok {
		t.peerHostname = hn
	}

	// Validate protocol version.
	if ver, ok := GetAVPBytes(avps, AVPProtocolVersion); ok {
		if len(ver) >= 2 && ver[0] != 1 {
			log.Warn("l2tp: unsupported protocol version", "version", ver[0], "revision", ver[1])
			t.sendStopCCN(5, 0, "unsupported version")
			return errUnsupportedVersion
		}
	}

	log.Info("l2tp: tunnel SCCRQ received",
		"local_tid", t.localTunnelID,
		"remote_tid", remoteTID,
		"peer", t.peerAddr,
		"peer_hostname", t.peerHostname,
	)

	// Build SCCRP.
	sccrpAVPs := SerializeAVPs([]AVP{
		NewMessageTypeAVP(MsgSCCRP),
		NewProtocolVersionAVP(),
		NewFramingCapAVP(),
		NewHostNameAVP(hostname),
		NewVendorNameAVP("SWAN-NG"),
		NewAssignedTunnelIDAVP(t.localTunnelID),
		NewReceiveWindowSizeAVP(defaultReceiveWindow),
		NewFirmwareRevisionAVP(0x0100),
		NewBearerCapAVP(),
	})

	t.state = TunnelWaitCtlConn
	t.control.Send(sccrpAVPs)

	return nil
}

// HandleSCCCN processes a Start-Control-Connection-Connected.
// Validates the response, transitions to established.
// Transitions: wait-ctl-conn → established.
func (t *Tunnel) HandleSCCCN(avps []AVP) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != TunnelWaitCtlConn {
		log.Warn("l2tp: SCCCN in unexpected state", "state", t.state)
		return errInvalidState
	}

	t.state = TunnelEstablished

	log.Info("l2tp: tunnel established",
		"local_tid", t.localTunnelID,
		"remote_tid", t.remoteTunnelID,
		"peer", t.peerAddr,
	)

	return nil
}

// HandleICRQ processes an Incoming-Call-Request.
// Creates a new session and sends ICRP.
func (t *Tunnel) HandleICRQ(avps []AVP) (*Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != TunnelEstablished {
		log.Warn("l2tp: ICRQ in non-established tunnel", "state", t.state)
		return nil, errInvalidState
	}

	// Extract peer's assigned session ID.
	remoteSessionID, ok := GetAVPUint16(avps, AVPAssignedSessionID)
	if !ok || remoteSessionID == 0 {
		log.Warn("l2tp: ICRQ missing Assigned Session ID")
		return nil, errMissingAVP
	}

	// Allocate local session ID.
	localSessionID := uint16(t.nextSessionID.Add(1))
	if localSessionID == 0 {
		localSessionID = uint16(t.nextSessionID.Add(1))
	}

	// Create session.
	sess := newSession(localSessionID, remoteSessionID, t)
	t.sessions[localSessionID] = sess

	log.Info("l2tp: session ICRQ received",
		"local_sid", localSessionID,
		"remote_sid", remoteSessionID,
		"tunnel", t.localTunnelID,
	)

	// Build ICRP.
	icrpAVPs := SerializeAVPs([]AVP{
		NewMessageTypeAVP(MsgICRP),
		NewAssignedSessionIDAVP(localSessionID),
	})

	t.control.Send(icrpAVPs)

	return sess, nil
}

// HandleICCN processes an Incoming-Call-Connected.
// Transitions the session to established state.
func (t *Tunnel) HandleICCN(sessionID uint16, avps []AVP) error {
	t.mu.Lock()
	sess, ok := t.sessions[sessionID]
	t.mu.Unlock()

	if !ok {
		log.Warn("l2tp: ICCN for unknown session", "session_id", sessionID)
		return errSessionNotFound
	}

	return sess.handleICCN(avps)
}

// HandleHello processes a Hello keepalive message.
// Responds with ZLB ACK.
func (t *Tunnel) HandleHello() {
	t.mu.Lock()
	t.lastActivity = time.Now()
	t.mu.Unlock()

	// ZLB ACK is sent by the control channel's Receive() caller.
	log.Debug("l2tp: Hello received", "tunnel", t.localTunnelID)
}

// HandleCDN processes a Call-Disconnect-Notify for a session.
func (t *Tunnel) HandleCDN(avps []AVP) {
	sessionID, ok := GetAVPUint16(avps, AVPAssignedSessionID)
	if !ok {
		log.Warn("l2tp: CDN missing Assigned Session ID")
		return
	}

	t.mu.Lock()
	sess, found := t.sessions[sessionID]
	if found {
		delete(t.sessions, sessionID)
	}
	t.mu.Unlock()

	if found {
		sess.close()
		log.Info("l2tp: session disconnected (CDN)",
			"session_id", sessionID,
			"tunnel", t.localTunnelID,
		)
	}
}

// HandleStopCCN processes a Stop-Control-Connection-Notification.
// Tears down all sessions and the tunnel.
func (t *Tunnel) HandleStopCCN(avps []AVP) {
	t.mu.Lock()
	t.state = TunnelDead

	// Close all sessions.
	for id, sess := range t.sessions {
		sess.close()
		delete(t.sessions, id)
	}
	t.mu.Unlock()

	// Send ZLB ACK.
	t.control.SendZLB()

	log.Info("l2tp: tunnel stopped (StopCCN)",
		"tunnel", t.localTunnelID,
		"peer", t.peerAddr,
	)
}

// SendStopCCN sends a StopCCN to tear down the tunnel.
func (t *Tunnel) SendStopCCN(resultCode uint16, errorCode uint16, errorMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sendStopCCN(resultCode, errorCode, errorMsg)
}

// sendStopCCN sends a StopCCN (must be called with lock held).
func (t *Tunnel) sendStopCCN(resultCode uint16, errorCode uint16, errorMsg string) {
	avps := SerializeAVPs([]AVP{
		NewMessageTypeAVP(MsgStopCCN),
		NewAssignedTunnelIDAVP(t.localTunnelID),
		NewResultCodeAVP(resultCode, errorCode, errorMsg),
	})

	t.state = TunnelDead
	t.control.Send(avps)
}

// SendCDN sends a CDN to tear down a session.
func (t *Tunnel) SendCDN(sessionID uint16, resultCode uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()

	avps := SerializeAVPs([]AVP{
		NewMessageTypeAVP(MsgCDN),
		NewAssignedSessionIDAVP(sessionID),
		NewResultCodeAVP(resultCode, 0, ""),
	})

	t.control.Send(avps)

	// Clean up session.
	if sess, ok := t.sessions[sessionID]; ok {
		sess.close()
		delete(t.sessions, sessionID)
	}
}

// GetSession returns a session by local session ID.
func (t *Tunnel) GetSession(sessionID uint16) *Session {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.sessions[sessionID]
}

// SessionCount returns the number of active sessions.
func (t *Tunnel) SessionCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.sessions)
}

// Run starts the tunnel's background goroutines (keepalive, retransmit).
// Blocks until context is cancelled or tunnel dies.
func (t *Tunnel) Run(ctx context.Context) {
	ctx, t.cancel = context.WithCancel(ctx)

	retransmitTicker := time.NewTicker(500 * time.Millisecond)
	defer retransmitTicker.Stop()

	helloTicker := time.NewTicker(t.helloInterval)
	defer helloTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-retransmitTicker.C:
			if !t.control.CheckRetransmit() {
				// Tunnel dead from retransmit timeout.
				return
			}
		case <-helloTicker.C:
			t.mu.Lock()
			if t.state != TunnelEstablished {
				t.mu.Unlock()
				continue
			}
			elapsed := time.Since(t.lastActivity)
			t.mu.Unlock()

			if elapsed >= t.helloInterval {
				t.sendHello()
			}
		}
	}
}

// sendHello sends an L2TP Hello keepalive message.
func (t *Tunnel) sendHello() {
	avps := SerializeAVPs([]AVP{
		NewMessageTypeAVP(MsgHello),
	})
	t.control.Send(avps)

	log.Debug("l2tp: Hello sent", "tunnel", t.localTunnelID)
}

// Close tears down the tunnel and all sessions.
func (t *Tunnel) Close() {
	t.mu.Lock()

	if t.state == TunnelEstablished || t.state == TunnelWaitCtlConn {
		t.sendStopCCN(1, 0, "shutdown")
	}

	for id, sess := range t.sessions {
		sess.close()
		delete(t.sessions, id)
	}

	t.state = TunnelDead
	t.mu.Unlock()

	if t.cancel != nil {
		t.cancel()
	}

	log.Info("l2tp: tunnel closed", "tunnel", t.localTunnelID)
}

// computeL2TPChallengeResponse computes the L2TP tunnel-level challenge response.
// Per RFC 2661 §5.1.1: CHAP-style using MD5(msgType + shared_secret + challenge).
// The ID value is the Message Type of the response message (2 for SCCRP, 3 for SCCCN).
func computeL2TPChallengeResponse(msgType byte, sharedSecret, challenge []byte) []byte {
	h := md5.New()
	h.Write([]byte{msgType})
	h.Write(sharedSecret)
	h.Write(challenge)
	return h.Sum(nil)
}

// Sentinel errors for tunnel operations.
var (
	errInvalidState       = &l2tpError{"invalid tunnel/session state"}
	errMissingAVP         = &l2tpError{"required AVP missing"}
	errSessionNotFound    = &l2tpError{"session not found"}
	errUnsupportedVersion = &l2tpError{"unsupported L2TP version"}
)

// l2tpError is a simple error type for L2TP operations.
type l2tpError struct {
	msg string
}

func (e *l2tpError) Error() string {
	return "l2tp: " + e.msg
}
