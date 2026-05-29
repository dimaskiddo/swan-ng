package l2tp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// LCP code values (RFC 1661 §5).
const (
	LCPConfigureRequest byte = 1
	LCPConfigureAck     byte = 2
	LCPConfigureNak     byte = 3
	LCPConfigureReject  byte = 4
	LCPTerminateRequest byte = 5
	LCPTerminateAck     byte = 6
	LCPCodeReject       byte = 7
	LCPProtocolReject   byte = 8
	LCPEchoRequest      byte = 9
	LCPEchoReply        byte = 10
	LCPDiscardRequest   byte = 11
)

// LCP option types (RFC 1661 §6).
const (
	LCPOptMRU          byte = 1 // Maximum-Receive-Unit
	LCPOptAuthProto    byte = 3 // Authentication-Protocol
	LCPOptQualityProto byte = 4 // Quality-Protocol
	LCPOptMagicNumber  byte = 5 // Magic-Number
	LCPOptPFCompress   byte = 7 // Protocol-Field-Compression
	LCPOptACFCompress  byte = 8 // Address-and-Control-Field-Compression
)

// LCP negotiation states (RFC 1661 §4.2, simplified).
const (
	LCPStateInitial byte = 0
	LCPStateReqSent byte = 1
	LCPStateAckRcvd byte = 2
	LCPStateAckSent byte = 3
	LCPStateOpened  byte = 4
	LCPStateClosed  byte = 5
)

// lcpPacketHeaderLen is Code(1) + ID(1) + Length(2) = 4.
const lcpPacketHeaderLen = 4

// lcpOptionHeaderLen is Type(1) + Length(1) = 2.
const lcpOptionHeaderLen = 2

// defaultMRU is the default Maximum-Receive-Unit.
const defaultMRU uint16 = 1500

// LCPHandler manages LCP negotiation for a PPP session.
// Implements server-side LCP per RFC 1661 §5.
type LCPHandler struct {
	// state tracks the LCP negotiation state.
	state byte
	// localMagic is our magic number for loop detection.
	localMagic uint32
	// remoteMagic is the peer's magic number.
	remoteMagic uint32
	// mru is the negotiated Maximum-Receive-Unit.
	mru uint16
	// nextID is the next identifier for outgoing LCP packets.
	nextID byte
	// ourConfigAcked tracks whether our Configure-Request was acknowledged.
	ourConfigAcked bool
	// peerConfigAcked tracks whether we acknowledged the peer's Configure-Request.
	peerConfigAcked bool
}

// NewLCPHandler creates a new LCP negotiation handler.
func NewLCPHandler() *LCPHandler {
	var magic [4]byte
	_, _ = rand.Read(magic[:])

	return &LCPHandler{
		state:      LCPStateInitial,
		localMagic: binary.BigEndian.Uint32(magic[:]),
		mru:        defaultMRU,
	}
}

// State returns the current LCP state.
func (h *LCPHandler) State() byte {
	return h.state
}

// IsOpened returns true when LCP negotiation is complete.
func (h *LCPHandler) IsOpened() bool {
	return h.state == LCPStateOpened
}

// BuildConfigureRequest generates our LCP Configure-Request.
// We request: MRU, Authentication-Protocol (CHAP MD5), and Magic-Number.
func (h *LCPHandler) BuildConfigureRequest() []byte {
	h.nextID++
	id := h.nextID

	// Build options.
	var opts []byte

	// MRU option: Type(1) + Length(1) + MRU(2) = 4 bytes.
	opts = append(opts, LCPOptMRU, 4)
	opts = append(opts, byte(h.mru>>8), byte(h.mru))

	// Authentication-Protocol: Type(1) + Length(1) + Proto(2) + Algorithm(1) = 5 bytes.
	// CHAP = 0xC223, Algorithm = 5 (MD5).
	opts = append(opts, LCPOptAuthProto, 5)
	opts = append(opts, byte(PPPProtoCHAP>>8), byte(PPPProtoCHAP&0xFF))
	opts = append(opts, CHAPAlgorithmMD5)

	// Magic-Number: Type(1) + Length(1) + Magic(4) = 6 bytes.
	opts = append(opts, LCPOptMagicNumber, 6)
	m := make([]byte, 4)
	binary.BigEndian.PutUint32(m, h.localMagic)
	opts = append(opts, m...)

	// Build LCP packet: Code + ID + Length + Options.
	pktLen := uint16(lcpPacketHeaderLen + len(opts))
	pkt := make([]byte, pktLen)
	pkt[0] = LCPConfigureRequest
	pkt[1] = id
	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	copy(pkt[4:], opts)

	if h.state == LCPStateInitial {
		h.state = LCPStateReqSent
	}

	return pkt
}

// Handle processes an incoming LCP packet and returns a response PPP payload (if any).
// Returns nil if no response is needed.
func (h *LCPHandler) Handle(data []byte) []byte {
	if len(data) < lcpPacketHeaderLen {
		log.Debug("lcp: packet too short", "len", len(data))
		return nil
	}

	code := data[0]
	id := data[1]
	pktLen := binary.BigEndian.Uint16(data[2:4])

	if int(pktLen) > len(data) {
		log.Debug("lcp: stated length exceeds data", "pkt_len", pktLen, "data_len", len(data))
		return nil
	}

	payload := data[lcpPacketHeaderLen:pktLen]

	switch code {
	case LCPConfigureRequest:
		return h.handleConfigureRequest(id, payload)
	case LCPConfigureAck:
		return h.handleConfigureAck(id)
	case LCPConfigureNak:
		return h.handleConfigureNak(id, payload)
	case LCPConfigureReject:
		return h.handleConfigureReject(id, payload)
	case LCPTerminateRequest:
		return h.handleTerminateRequest(id)
	case LCPEchoRequest:
		return h.handleEchoRequest(id, payload)
	case LCPProtocolReject:
		log.Debug("lcp: received Protocol-Reject", "id", id)
		return nil
	default:
		log.Debug("lcp: unknown code", "code", code, "id", id)
		return nil
	}
}

// handleConfigureRequest processes a peer's Configure-Request.
// We accept MRU, Magic-Number. We Nak if auth is not CHAP. We Reject unknowns.
func (h *LCPHandler) handleConfigureRequest(id byte, options []byte) []byte {
	var ackOpts []byte
	var nakOpts []byte
	var rejOpts []byte

	offset := 0
	for offset < len(options) {
		if offset+lcpOptionHeaderLen > len(options) {
			break
		}
		optType := options[offset]
		optLen := int(options[offset+1])
		if optLen < lcpOptionHeaderLen || offset+optLen > len(options) {
			break
		}

		optData := options[offset : offset+optLen]

		switch optType {
		case LCPOptMRU:
			// Accept any reasonable MRU.
			if optLen >= 4 {
				peerMRU := binary.BigEndian.Uint16(optData[2:4])
				if peerMRU >= 128 && peerMRU <= 16384 {
					h.mru = peerMRU
					ackOpts = append(ackOpts, optData...)
				} else {
					// Nak with our default.
					nak := []byte{LCPOptMRU, 4, byte(defaultMRU >> 8), byte(defaultMRU & 0xFF)}
					nakOpts = append(nakOpts, nak...)
				}
			} else {
				rejOpts = append(rejOpts, optData...)
			}

		case LCPOptAuthProto:
			// We require CHAP MD5. Nak anything else.
			if optLen >= 4 {
				proto := binary.BigEndian.Uint16(optData[2:4])
				if proto == PPPProtoCHAP {
					ackOpts = append(ackOpts, optData...)
				} else {
					// Nak: suggest CHAP MD5.
					nak := []byte{LCPOptAuthProto, 5, byte(PPPProtoCHAP >> 8), byte(PPPProtoCHAP & 0xFF), CHAPAlgorithmMD5}
					nakOpts = append(nakOpts, nak...)
				}
			} else {
				rejOpts = append(rejOpts, optData...)
			}

		case LCPOptMagicNumber:
			if optLen >= 6 {
				h.remoteMagic = binary.BigEndian.Uint32(optData[2:6])
				ackOpts = append(ackOpts, optData...)
			} else {
				rejOpts = append(rejOpts, optData...)
			}

		case LCPOptPFCompress:
			// Accept Protocol-Field-Compression.
			ackOpts = append(ackOpts, optData...)

		case LCPOptACFCompress:
			// Accept Address-and-Control-Field-Compression.
			ackOpts = append(ackOpts, optData...)

		default:
			// Reject unknown options.
			rejOpts = append(rejOpts, optData...)
			log.Debug("lcp: rejecting unknown option", "type", optType)
		}

		offset += optLen
	}

	// Priority: Reject > Nak > Ack (RFC 1661 §5.2).
	if len(rejOpts) > 0 {
		return h.buildResponse(LCPConfigureReject, id, rejOpts)
	}
	if len(nakOpts) > 0 {
		return h.buildResponse(LCPConfigureNak, id, nakOpts)
	}

	// All options accepted.
	h.peerConfigAcked = true
	h.checkOpened()

	return h.buildResponse(LCPConfigureAck, id, ackOpts)
}

// handleConfigureAck processes peer's acknowledgment of our Configure-Request.
func (h *LCPHandler) handleConfigureAck(id byte) []byte {
	if id != h.nextID {
		log.Debug("lcp: Configure-Ack ID mismatch", "expected", h.nextID, "got", id)
		return nil
	}

	h.ourConfigAcked = true
	h.checkOpened()

	return nil
}

// handleConfigureNak processes peer's Nak of our Configure-Request.
// Adjusts parameters and re-sends Configure-Request.
func (h *LCPHandler) handleConfigureNak(id byte, options []byte) []byte {
	// Parse nak'd options and adjust our parameters.
	offset := 0
	for offset < len(options) {
		if offset+lcpOptionHeaderLen > len(options) {
			break
		}
		optType := options[offset]
		optLen := int(options[offset+1])
		if optLen < lcpOptionHeaderLen || offset+optLen > len(options) {
			break
		}

		optData := options[offset : offset+optLen]

		switch optType {
		case LCPOptMRU:
			if optLen >= 4 {
				h.mru = binary.BigEndian.Uint16(optData[2:4])
			}
		case LCPOptAuthProto:
			// Peer doesn't want our auth. We insist on CHAP — resend.
			log.Debug("lcp: peer nak'd auth, re-requesting CHAP")
		case LCPOptMagicNumber:
			// Collision — regenerate magic.
			var magic [4]byte
			_, _ = rand.Read(magic[:])
			h.localMagic = binary.BigEndian.Uint32(magic[:])
		}

		offset += optLen
	}

	// Re-send Configure-Request with adjusted parameters.
	return h.BuildConfigureRequest()
}

// handleConfigureReject processes peer's Reject of our Configure-Request.
// Removes rejected options and re-sends.
func (h *LCPHandler) handleConfigureReject(id byte, options []byte) []byte {
	// Log rejected options. For our implementation, we can't remove
	// CHAP auth requirement — if peer rejects auth, session will fail.
	offset := 0
	for offset < len(options) {
		if offset+lcpOptionHeaderLen > len(options) {
			break
		}
		optType := options[offset]
		optLen := int(options[offset+1])
		if optLen < lcpOptionHeaderLen || offset+optLen > len(options) {
			break
		}

		switch optType {
		case LCPOptAuthProto:
			// Peer rejects authentication entirely.
			// Per AGENTS.md: CHAP is required. Cannot proceed without auth.
			log.Warn("lcp: peer rejected authentication, session cannot proceed")
			h.state = LCPStateClosed
			return h.buildResponse(LCPTerminateRequest, h.nextID, []byte("Authentication required"))
		case LCPOptMagicNumber:
			log.Debug("lcp: peer rejected magic number, removing")
			h.localMagic = 0
		}

		offset += optLen
	}

	return h.BuildConfigureRequest()
}

// handleTerminateRequest processes a peer's Terminate-Request.
func (h *LCPHandler) handleTerminateRequest(id byte) []byte {
	h.state = LCPStateClosed
	log.Info("lcp: received Terminate-Request")
	return h.buildResponse(LCPTerminateAck, id, nil)
}

// handleEchoRequest processes a peer's Echo-Request.
// Responds with Echo-Reply containing our Magic-Number per RFC 1661 §5.8.
func (h *LCPHandler) handleEchoRequest(id byte, payload []byte) []byte {
	// Echo-Reply: Code(10) + ID + Length + Magic-Number(4) + Data.
	// The Magic-Number in the reply is our own.
	var reply []byte
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, h.localMagic)
	reply = append(reply, magic...)

	// Append any data after the peer's magic number (skip first 4 bytes).
	if len(payload) > 4 {
		reply = append(reply, payload[4:]...)
	}

	return h.buildResponse(LCPEchoReply, id, reply)
}

// checkOpened transitions to Opened state when both sides have acknowledged.
func (h *LCPHandler) checkOpened() {
	if h.ourConfigAcked && h.peerConfigAcked {
		h.state = LCPStateOpened
		log.Info("lcp: negotiation complete",
			"mru", h.mru,
			"local_magic", fmt.Sprintf("0x%08X", h.localMagic),
			"remote_magic", fmt.Sprintf("0x%08X", h.remoteMagic),
		)
	}
}

// buildResponse constructs an LCP response packet.
func (h *LCPHandler) buildResponse(code, id byte, data []byte) []byte {
	pktLen := uint16(lcpPacketHeaderLen + len(data))
	pkt := make([]byte, pktLen)
	pkt[0] = code
	pkt[1] = id
	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	if len(data) > 0 {
		copy(pkt[4:], data)
	}
	return pkt
}

// BuildProtocolReject creates an LCP Protocol-Reject message for an unsupported PPP protocol.
// Per RFC 1661 §5.7, the rejected packet (truncated to peer's MRU) is included.
func (h *LCPHandler) BuildProtocolReject(rejectedProto uint16, rejectedPacket []byte) []byte {
	h.nextID++

	// Include rejected protocol (2 bytes) + as much of rejected packet as fits in MRU.
	maxData := int(h.mru) - lcpPacketHeaderLen - 2
	if maxData < 0 {
		maxData = 0
	}

	var data []byte
	proto := make([]byte, 2)
	binary.BigEndian.PutUint16(proto, rejectedProto)
	data = append(data, proto...)

	if len(rejectedPacket) > maxData {
		data = append(data, rejectedPacket[:maxData]...)
	} else {
		data = append(data, rejectedPacket...)
	}

	return h.buildResponse(LCPProtocolReject, h.nextID, data)
}
