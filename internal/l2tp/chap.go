package l2tp

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// CHAP code values (RFC 1994 §4).
const (
	CHAPChallenge byte = 1
	CHAPResponse  byte = 2
	CHAPSuccess   byte = 3
	CHAPFailure   byte = 4
)

// CHAP algorithm identifiers.
const (
	// CHAPAlgorithmMD5 is CHAP with MD5 (RFC 1994 §4.1).
	CHAPAlgorithmMD5 byte = 5
)

// chapPacketHeaderLen is Code(1) + ID(1) + Length(2) = 4.
const chapPacketHeaderLen = 4

// UserDatabase provides user credential lookup for CHAP authentication.
// Implementations must be safe for concurrent use.
type UserDatabase interface {
	// LookupUser returns the password for a given username.
	// Returns ("", false) if user not found.
	LookupUser(username string) (password string, found bool)
}

// CHAPHandler manages CHAP authentication for a PPP session.
// Implements server-side CHAP per RFC 1994.
//
// Flow:
//  1. Server sends Challenge (random value + server name)
//  2. Client sends Response (MD5(ID + password + challenge) + username)
//  3. Server verifies response, sends Success or Failure
type CHAPHandler struct {
	// challengeID is the CHAP identifier for the current challenge.
	challengeID byte
	// challenge is the random challenge value (16 bytes).
	challenge []byte
	// serverName is the server's identity sent in the Challenge.
	serverName string
	// userDB provides credential lookup.
	userDB UserDatabase
	// authenticated tracks if authentication succeeded.
	authenticated bool
	// username stores the authenticated username.
	username string
}

// NewCHAPHandler creates a new CHAP handler.
func NewCHAPHandler(serverName string, userDB UserDatabase) *CHAPHandler {
	return &CHAPHandler{
		serverName: serverName,
		userDB:     userDB,
	}
}

// IsAuthenticated returns true if the peer was successfully authenticated.
func (h *CHAPHandler) IsAuthenticated() bool {
	return h.authenticated
}

// Username returns the authenticated username (empty if not authenticated).
func (h *CHAPHandler) Username() string {
	return h.username
}

// BuildChallenge generates a CHAP Challenge packet.
// The challenge is 16 random bytes. The Name field is the server hostname.
//
// CHAP Challenge format (RFC 1994 §4.1):
//
//	Code(1) + ID(1) + Length(2) + Value-Size(1) + Value(N) + Name(...)
func (h *CHAPHandler) BuildChallenge() []byte {
	h.challengeID++

	// Generate 16-byte random challenge.
	h.challenge = make([]byte, 16)
	_, _ = rand.Read(h.challenge)

	nameBytes := []byte(h.serverName)
	valueSize := byte(len(h.challenge))

	// Total length: header(4) + value-size(1) + value(16) + name.
	totalLen := uint16(chapPacketHeaderLen + 1 + len(h.challenge) + len(nameBytes))

	pkt := make([]byte, totalLen)
	pkt[0] = CHAPChallenge
	pkt[1] = h.challengeID

	binary.BigEndian.PutUint16(pkt[2:4], totalLen)

	pkt[4] = valueSize

	copy(pkt[5:5+len(h.challenge)], h.challenge)
	copy(pkt[5+len(h.challenge):], nameBytes)

	log.Debug("chap: sending challenge",
		"id", h.challengeID,
		"challenge_len", len(h.challenge),
	)

	return pkt
}

// Handle processes an incoming CHAP packet and returns a response (if any).
// Only processes CHAP Response packets from the peer.
func (h *CHAPHandler) Handle(data []byte) []byte {
	if len(data) < chapPacketHeaderLen {
		log.Debug("chap: packet too short", "len", len(data))
		return nil
	}

	code := data[0]
	id := data[1]
	pktLen := binary.BigEndian.Uint16(data[2:4])

	if int(pktLen) > len(data) {
		log.Debug("chap: stated length exceeds data", "pkt_len", pktLen, "data_len", len(data))
		return nil
	}

	switch code {
	case CHAPResponse:
		return h.handleResponse(id, data[chapPacketHeaderLen:pktLen])

	default:
		log.Debug("chap: unexpected code", "code", code, "id", id)
		return nil
	}
}

// handleResponse processes a CHAP Response from the peer.
//
// CHAP Response format (RFC 1994 §4.1):
//
//	Value-Size(1) + Value(N) + Name(...)
//
// Verification: MD5(ID + password + challenge) must equal the Response Value.
func (h *CHAPHandler) handleResponse(id byte, payload []byte) []byte {
	if len(payload) < 1 {
		log.Warn("chap: empty response payload")
		return h.buildFailure(id, "malformed response")
	}

	valueSize := int(payload[0])
	if 1+valueSize > len(payload) {
		log.Warn("chap: response value-size exceeds payload",
			"value_size", valueSize,
			"payload_len", len(payload),
		)

		return h.buildFailure(id, "malformed response")
	}

	responseValue := payload[1 : 1+valueSize]
	peerName := string(payload[1+valueSize:])

	log.Debug("chap: received response",
		"id", id,
		"username", peerName,
		"value_size", valueSize,
	)

	// Lookup user in database.
	password, found := h.userDB.LookupUser(peerName)
	if !found {
		log.Warn("chap: unknown user", "username", peerName)
		return h.buildFailure(id, "authentication failed")
	}

	// Verify: MD5(ID || password || challenge).
	expected := h.computeMD5Response(id, password)

	if len(responseValue) != len(expected) {
		log.Warn("chap: response size mismatch",
			"username", peerName,
			"expected_size", len(expected),
			"got_size", len(responseValue),
		)
		return h.buildFailure(id, "authentication failed")
	}

	// Constant-time comparison to prevent timing attacks.
	match := true
	for i := range expected {
		if responseValue[i] != expected[i] {
			match = false
		}
	}

	if !match {
		log.Warn("chap: authentication failed", "username", peerName)
		return h.buildFailure(id, "authentication failed")
	}

	// Authentication successful.
	h.authenticated = true
	h.username = peerName

	log.Info("chap: authentication successful", "username", peerName)
	return h.buildSuccess(id, fmt.Sprintf("Welcome %s", peerName))
}

// computeMD5Response computes the expected CHAP MD5 response.
// Per RFC 1994 §4.1: MD5(ID || Secret || Challenge).
func (h *CHAPHandler) computeMD5Response(id byte, secret string) []byte {
	hash := md5.New()

	hash.Write([]byte{id})
	hash.Write([]byte(secret))
	hash.Write(h.challenge)

	return hash.Sum(nil)
}

// buildSuccess creates a CHAP Success message.
//
// Format: Code(3) + ID(1) + Length(2) + Message(...)
func (h *CHAPHandler) buildSuccess(id byte, message string) []byte {
	msgBytes := []byte(message)
	totalLen := uint16(chapPacketHeaderLen + len(msgBytes))

	pkt := make([]byte, totalLen)
	pkt[0] = CHAPSuccess
	pkt[1] = id

	binary.BigEndian.PutUint16(pkt[2:4], totalLen)
	copy(pkt[4:], msgBytes)

	return pkt
}

// buildFailure creates a CHAP Failure message.
//
// Format: Code(4) + ID(1) + Length(2) + Message(...)
func (h *CHAPHandler) buildFailure(id byte, message string) []byte {
	msgBytes := []byte(message)
	totalLen := uint16(chapPacketHeaderLen + len(msgBytes))

	pkt := make([]byte, totalLen)
	pkt[0] = CHAPFailure
	pkt[1] = id

	binary.BigEndian.PutUint16(pkt[2:4], totalLen)
	copy(pkt[4:], msgBytes)

	return pkt
}
