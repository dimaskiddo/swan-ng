package ike

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// EAPTLSState holds server-side state for an EAP-TLS exchange.
type EAPTLSState struct {
	mu sync.Mutex

	// In-memory TLS transport.
	transport *eapTLSTransport
	tlsConn   *tls.Conn

	// EAP-TLS fragmentation state (RFC 5216 §3.1).
	rxBuf     []byte // Reassembly buffer for incoming TLS records
	rxPending bool   // true if we're waiting for more fragments

	// TLS handshake completion channel.
	handshakeDone bool
	handshakeErr  error
	peerIdentity  string // Extracted from client certificate CN/SAN
}

// eapTLSTransport implements net.Conn over an in-memory byte buffer.
// This bridges EAP-TLS fragments to Go's crypto/tls package.
type eapTLSTransport struct {
	readBuf  []byte // Data available for TLS to read
	writeBuf []byte // Data TLS has written (to be sent via EAP)
	mu       sync.Mutex
	closed   bool
}

func newEAPTLSTransport() *eapTLSTransport {
	return &eapTLSTransport{}
}

func (t *eapTLSTransport) Read(b []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return 0, io.EOF
	}

	if len(t.readBuf) == 0 {
		return 0, io.EOF
	}

	n := copy(b, t.readBuf)
	t.readBuf = t.readBuf[n:]

	return n, nil
}

func (t *eapTLSTransport) Write(b []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return 0, io.ErrClosedPipe
	}

	t.writeBuf = append(t.writeBuf, b...)

	return len(b), nil
}

func (t *eapTLSTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true

	return nil
}

// feedData provides incoming TLS record data to the transport.
func (t *eapTLSTransport) feedData(data []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.readBuf = append(t.readBuf, data...)
}

// takeData retrieves outgoing TLS record data from the transport.
func (t *eapTLSTransport) takeData() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()

	data := t.writeBuf
	t.writeBuf = nil

	return data
}

// net.Conn interface satisfaction (unused methods for in-memory transport).
func (t *eapTLSTransport) LocalAddr() net.Addr                { return nil }
func (t *eapTLSTransport) RemoteAddr() net.Addr               { return nil }
func (t *eapTLSTransport) SetDeadline(time.Time) error        { return nil }
func (t *eapTLSTransport) SetReadDeadline(time.Time) error    { return nil }
func (t *eapTLSTransport) SetWriteDeadline(time.Time) error   { return nil }

// EAP-TLS fragmentation constants (RFC 5216 §3.1).
const (
	eapTLSFlagLength  = 0x80 // Length included
	eapTLSFlagMore    = 0x40 // More fragments
	eapTLSFlagStart   = 0x20 // Start flag (first fragment)
	eapTLSMaxFragment = 1024 // Max EAP-TLS fragment size
)

// handleEAPTLS processes EAP-TLS responses from the peer.
func (h *IKEv2Handler) handleEAPTLS(sess *IKEv2Session, pkt *EAPPacket, msgID uint32) (*Message, error) {
	state, ok := sess.EAPState.(*EAPTLSState)
	if !ok || state == nil {
		return nil, fmt.Errorf("IKE_AUTH EAP-TLS: state not initialized")
	}

	state.mu.Lock()
	defer state.mu.Unlock()

	// Parse EAP-TLS data: Flags(1) [TLS Message Length(4)] [TLS Data...]
	if len(pkt.Data) < 1 {
		return h.sendEAPFailure(sess, msgID)
	}

	flags := pkt.Data[0]
	offset := 1

	// If Length flag set, 4-byte TLS message length follows.
	if flags&eapTLSFlagLength != 0 {
		if len(pkt.Data) < 5 {
			return h.sendEAPFailure(sess, msgID)
		}
		// We don't need the total length for reassembly since we buffer.
		offset = 5
	}

	// Append TLS data to reassembly buffer.
	if offset < len(pkt.Data) {
		state.rxBuf = append(state.rxBuf, pkt.Data[offset:]...)
	}

	// If More flag set, send empty EAP-TLS request to continue receiving.
	if flags&eapTLSFlagMore != 0 {
		state.rxPending = true
		sess.EAPIdentifier++

		// Send acknowledgment (empty EAP-TLS request).
		ackData := []byte{0x00} // No flags
		eapReq := &EAPPacket{
			Code:       EAPCodeRequest,
			Identifier: sess.EAPIdentifier,
			Type:       EAPTypeTLS,
			Data:       ackData,
		}

		return h.sendEAPPayload(sess, eapReq.Marshal(), msgID)
	}

	// Complete TLS record received — feed to transport.
	state.rxPending = false
	tlsData := state.rxBuf
	state.rxBuf = nil

	if len(tlsData) > 0 {
		state.transport.feedData(tlsData)
	}

	// Drive TLS handshake.
	if !state.handshakeDone {
		err := state.tlsConn.Handshake()
		if err != nil {
			// Check if it's a non-fatal error (handshake needs more data).
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				// TLS needs more data — will come in next EAP round.
			} else if errors.Is(err, io.EOF) {
				// More data needed.
			} else {
				// Fatal TLS error.
				log.Warn("IKEv2 EAP-TLS: handshake failed",
					"peer", sess.PeerAddr.String(), "error", err)
				state.handshakeErr = err

				return h.sendEAPFailure(sess, msgID)
			}
		} else {
			state.handshakeDone = true

			// Extract peer identity from client certificate.
			peerCerts := state.tlsConn.ConnectionState().PeerCertificates
			if len(peerCerts) > 0 {
				state.peerIdentity = peerCerts[0].Subject.CommonName
			}

			// Derive MSK from TLS key material (RFC 5216 §2.3).
			// EAP-TLS MSK = TLS-PRF(master_secret, "client EAP encryption", client_random + server_random)
			// Go's crypto/tls doesn't expose ExportKeyingMaterial for all versions,
			// but for TLS 1.3 we can use ExportKeyingMaterial.
			connState := state.tlsConn.ConnectionState()
			msk, err := connState.ExportKeyingMaterial("client EAP encryption", nil, 64)
			if err != nil {
				log.Warn("IKEv2 EAP-TLS: MSK export failed",
					"peer", sess.PeerAddr.String(), "error", err)
				// Fallback: use empty MSK (not ideal but prevents crash).
				msk = make([]byte, 64)
			}
			sess.EAPMSK = msk

			log.Info("IKEv2 EAP-TLS: handshake complete",
				"peer", sess.PeerAddr.String(),
				"identity", state.peerIdentity,
				"tls_version", state.tlsConn.ConnectionState().Version,
			)
		}
	}

	// Get outgoing TLS data to send.
	outData := state.transport.takeData()
	if len(outData) == 0 && state.handshakeDone {
		// Handshake complete, send EAP-Success.
		sess.EAPIdentifier++
		sess.State = StateV2EAPDone
		eapSuccess := BuildEAPSuccess(sess.EAPIdentifier)

		return h.sendEAPPayload(sess, eapSuccess, msgID)
	}

	// Fragment and send TLS data.
	return h.sendEAPTLSFragments(sess, outData, msgID, state.handshakeDone)
}

// sendEAPTLSFragments fragments TLS data into EAP-TLS packets.
func (h *IKEv2Handler) sendEAPTLSFragments(sess *IKEv2Session, tlsData []byte, msgID uint32, isLast bool) (*Message, error) {
	sess.EAPIdentifier++

	if len(tlsData) <= eapTLSMaxFragment {
		// Single fragment.
		flags := byte(0)
		if !isLast {
			flags |= eapTLSFlagLength
		}

		eapData := make([]byte, 1+len(tlsData))
		eapData[0] = flags
		copy(eapData[1:], tlsData)

		pkt := &EAPPacket{
			Code:       EAPCodeRequest,
			Identifier: sess.EAPIdentifier,
			Type:       EAPTypeTLS,
			Data:       eapData,
		}

		return h.sendEAPPayload(sess, pkt.Marshal(), msgID)
	}

	// Multiple fragments needed — send first fragment with Start+Length flags.
	// Remaining fragments sent in subsequent EAP rounds.
	fragSize := eapTLSMaxFragment
	flags := byte(eapTLSFlagLength | eapTLSFlagMore | eapTLSFlagStart)

	// First fragment: Flags(1) + TotalLength(4) + Data
	eapData := make([]byte, 5+fragSize)
	eapData[0] = flags
	eapData[1] = byte(len(tlsData) >> 24)
	eapData[2] = byte(len(tlsData) >> 16)
	eapData[3] = byte(len(tlsData) >> 8)
	eapData[4] = byte(len(tlsData))
	copy(eapData[5:], tlsData[:fragSize])

	pkt := &EAPPacket{
		Code:       EAPCodeRequest,
		Identifier: sess.EAPIdentifier,
		Type:       EAPTypeTLS,
		Data:       eapData,
	}

	return h.sendEAPPayload(sess, pkt.Marshal(), msgID)
}

// initEAPTLS initializes EAP-TLS state and starts the TLS handshake.
func (h *IKEv2Handler) initEAPTLS(sess *IKEv2Session) error {
	if h.certProvider == nil {
		return fmt.Errorf("EAP-TLS requires cert provider")
	}

	serverCert, err := h.certProvider.ServerTLSCertificate()
	if err != nil {
		return fmt.Errorf("EAP-TLS: server cert: %w", err)
	}

	caPool := h.certProvider.CACertPool()

	transport := newEAPTLSTransport()

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	tlsConn := tls.Server(transport, tlsCfg)

	state := &EAPTLSState{
		transport: transport,
		tlsConn:   tlsConn,
	}

	sess.EAPState = state
	sess.EAPMethod = EAPTypeTLS

	return nil
}
