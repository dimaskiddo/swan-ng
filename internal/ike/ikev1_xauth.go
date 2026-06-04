package ike

import (
	"encoding/binary"
	"fmt"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// ISAKMP Configuration Method types (RFC 2408 / draft-ietf-ipsec-isakmp-mode-cfg-05).
const (
	ISAKMPCfgRequest uint8 = 1
	ISAKMPCfgReply   uint8 = 2
	ISAKMPCfgSet     uint8 = 3
	ISAKMPCfgAck     uint8 = 4
)

// HandleTransaction processes IKEv1 Transaction Exchange messages.
// Transaction Exchange (type 6) is used for XAUTH authentication
// and Mode Config (ISAKMP Config Method) per draft-ietf-ipsec-isakmp-xauth-06.
//
// Flow (server-initiated XAUTH):
//  1. Server → Client: XAUTH REQUEST (username + password attributes)
//  2. Client → Server: XAUTH REPLY (filled username + password)
//  3. Server → Client: XAUTH SET (STATUS = OK/FAIL)
//  4. Client → Server: XAUTH ACK
func (h *IKEv1Handler) HandleTransaction(sess *IKEv1Session, packetData []byte, hdr Header) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV1XAUTHSent && sess.State != StateV1Established {
		return nil, fmt.Errorf("XAUTH: unexpected state %s", sess.State)
	}

	msgID := hdr.MessageID

	// Compute Transaction Exchange IV.
	blockSize := 16
	if sess.Encryptor != nil {
		blockSize = sess.Encryptor.BlockSize()
	}

	txIV := ComputeV1QuickModeIV(sess.HashAlg, sess.CurrentIV, msgID, blockSize)

	// Decrypt encrypted payload.
	encPayload := packetData[HeaderLen:]
	decrypted, err := DecryptIKEv1Payload(sess.Encryptor, sess.Keys.SKEYID_e, txIV, encPayload)
	if err != nil {
		return nil, fmt.Errorf("XAUTH: decrypt: %w", err)
	}

	// Update IV for this exchange.
	if len(encPayload) >= blockSize {
		txIV = make([]byte, blockSize)
		copy(txIV, encPayload[len(encPayload)-blockSize:])
	}

	// Parse decrypted payloads.
	chain, err := ParsePayloadChain(decrypted, hdr.NextPayload, false)
	if err != nil {
		return nil, fmt.Errorf("XAUTH: parse: %w", err)
	}

	// Verify HASH payload.
	hashPayload := findPayloadAs[*HashV1Payload](chain)
	if hashPayload == nil {
		return nil, fmt.Errorf("XAUTH: missing Hash payload")
	}

	// Process based on current state.
	switch sess.State {
	case StateV1XAUTHSent:
		// Expecting XAUTH REPLY with username and password.
		return h.handleXAUTHReply(sess, chain, msgID, txIV)

	default:
		// Unexpected state for transaction.
		return nil, fmt.Errorf("XAUTH: unexpected transaction in state %s", sess.State)
	}
}

// InitiateXAUTH sends the initial XAUTH challenge (username + password request).
// Called after Phase 1 Main Mode completes when XAUTH auth method was negotiated.
func (h *IKEv1Handler) InitiateXAUTH(sess *IKEv1Session) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV1Established {
		return nil, fmt.Errorf("XAUTH initiate: not established (state %s)", sess.State)
	}

	// Generate a unique message ID for this exchange.
	sess.NextMsgID++
	msgID := sess.NextMsgID

	// Build XAUTH Request attributes: ask for username and password.
	attrs := []ISAKMPAttribute{
		{Type: XAUTH_TYPE, IsTV: true, Value: []byte{0, 0}},       // Type = Generic (0)
		{Type: XAUTH_USER_NAME, IsTV: false, Value: []byte{}},     // Empty = request
		{Type: XAUTH_USER_PASSWORD, IsTV: false, Value: []byte{}}, // Empty = request
	}

	return h.buildXAUTHMessage(sess, msgID, ISAKMPCfgRequest, attrs)
}

// handleXAUTHReply processes the client's XAUTH reply containing username and password.
func (h *IKEv1Handler) handleXAUTHReply(sess *IKEv1Session, chain PayloadChain, msgID uint32, iv []byte) (*Message, error) {
	// Find ISAKMP Config (Attribute) payload — these are carried as
	// generic payloads with Mode Config attributes.
	// In Transaction Exchange, the attributes follow the Hash payload.
	var username, password string

	for _, p := range chain {
		raw, ok := p.Payload.(*RawPayload)
		if !ok {
			continue
		}

		// Parse ISAKMP Config payload: Type(1) | Reserved(3) | Attributes...
		if len(raw.Data) < 4 {
			continue
		}

		// Extract attributes.
		attrData := raw.Data[4:]
		attrs := ParseISAKMPAttributes(attrData)

		for _, attr := range attrs {
			switch attr.Type {
			case XAUTH_USER_NAME:
				username = string(attr.Value)

			case XAUTH_USER_PASSWORD:
				password = string(attr.Value)
			}
		}
	}

	if username == "" {
		log.Warn("XAUTH: client sent empty username", "peer", sess.PeerAddr.String())
		return h.buildXAUTHResult(sess, msgID, false)
	}

	// Verify credentials using the handler's user lookup function.
	if h.getXAUTHCredentials == nil {
		log.Warn("XAUTH: no credential lookup configured", "peer", sess.PeerAddr.String())
		return h.buildXAUTHResult(sess, msgID, false)
	}

	valid := h.getXAUTHCredentials(username, password)
	if !valid {
		log.Warn("XAUTH: authentication failed",
			"peer", sess.PeerAddr.String(),
			"user", username,
		)

		return h.buildXAUTHResult(sess, msgID, false)
	}

	sess.XAUTHUser = username
	sess.State = StateV1XAUTHDone

	log.Info("IKEv1 XAUTH authenticated",
		"peer", sess.PeerAddr.String(),
		"user", username,
	)

	return h.buildXAUTHResult(sess, msgID, true)
}

// buildXAUTHMessage builds an encrypted Transaction Exchange message with
// ISAKMP Config attributes.
func (h *IKEv1Handler) buildXAUTHMessage(sess *IKEv1Session, msgID uint32, cfgType uint8, attrs []ISAKMPAttribute) (*Message, error) {
	// Build ISAKMP Config payload body: Type(1) | Reserved(3) | Attributes...
	var attrBytes []byte
	for _, attr := range attrs {
		attrBytes = append(attrBytes, attr.Marshal()...)
	}

	cfgBody := make([]byte, 4+len(attrBytes))
	cfgBody[0] = cfgType

	// bytes 1-3 reserved (zero)
	copy(cfgBody[4:], attrBytes)

	// Build Hash payload.
	hashInput := make([]byte, 4)
	binary.BigEndian.PutUint32(hashInput, msgID)
	hashInput = append(hashInput, cfgBody...)

	hashData := sess.PRF.Compute(sess.Keys.SKEYID_a, hashInput)

	// Build payload chain: Hash + Config payload (as RawPayload with type 14 = ISAKMP_CFG).
	respPayloads := []Payload{
		&HashV1Payload{HashData: hashData},
		&RawPayload{PayloadType: PayloadType(14), Data: cfgBody}, // ISAKMP_CFG = 14
	}

	respPayloadBytes, firstPT, err := MarshalPayloadChain(respPayloads)
	if err != nil {
		return nil, fmt.Errorf("XAUTH: marshal: %w", err)
	}

	// Compute IV for this message.
	blockSize := 16
	if sess.Encryptor != nil {
		blockSize = sess.Encryptor.BlockSize()
	}

	txIV := ComputeV1QuickModeIV(sess.HashAlg, sess.CurrentIV, msgID, blockSize)

	// Encrypt.
	encResp, err := EncryptIKEv1Payload(sess.Encryptor, sess.Keys.SKEYID_e, txIV, respPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("XAUTH: encrypt: %w", err)
	}

	// Build response message.
	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.CookieI,
			ResponderSPI: sess.CookieR,
			NextPayload:  firstPT,
			ExchangeType: ExchangeTransaction,
			Flags:        FlagV1Encryption,
			MessageID:    msgID,
			Length:       uint32(HeaderLen + len(encResp)),
		},
	}
	resp.Header.SetIKEv1()

	rawResp := make([]byte, HeaderLen+len(encResp))
	if err := resp.Header.Marshal(rawResp); err != nil {
		return nil, err
	}

	copy(rawResp[HeaderLen:], encResp)
	resp.RawMessage = rawResp

	if cfgType == ISAKMPCfgRequest {
		sess.State = StateV1XAUTHSent
	}

	return resp, nil
}

// buildXAUTHResult builds an XAUTH SET message with STATUS attribute.
func (h *IKEv1Handler) buildXAUTHResult(sess *IKEv1Session, msgID uint32, success bool) (*Message, error) {
	statusVal := uint16(0) // Failure
	if success {
		statusVal = 1 // OK
	}

	attrs := []ISAKMPAttribute{
		{Type: XAUTH_STATUS, IsTV: true, Value: []byte{byte(statusVal >> 8), byte(statusVal)}},
	}

	return h.buildXAUTHMessage(sess, msgID, ISAKMPCfgSet, attrs)
}
