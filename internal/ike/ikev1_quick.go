package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// HandleQuickMode1 processes Quick Mode message 1 from initiator.
// Creates a Child SA (Phase 2) and returns message 2.
// RFC 2409 §5.5.
func (h *IKEv1Handler) HandleQuickMode1(sess *IKEv1Session, msg *Message) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV1Established {
		return nil, fmt.Errorf("Quick Mode: Phase 1 not established (state %s)", sess.State)
	}

	msgID := msg.Header.MessageID

	// Compute Quick Mode IV.
	blockSize := 16
	if sess.Encryptor != nil {
		blockSize = sess.Encryptor.BlockSize()
	}
	qmIV := ComputeV1QuickModeIV(sess.HashAlg, sess.CurrentIV, msgID, blockSize)

	// Message is encrypted — decrypt.
	msgBytes, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("Quick Mode msg1: marshal for decrypt: %w", err)
	}

	encPayload := msgBytes[HeaderLen:]
	decrypted, err := DecryptIKEv1Payload(sess.Encryptor, sess.Keys.SKEYID_e, qmIV, encPayload)
	if err != nil {
		return nil, fmt.Errorf("Quick Mode msg1: decrypt: %w", err)
	}

	// Update IV for this QM exchange.
	if len(encPayload) >= blockSize {
		qmIV = make([]byte, blockSize)
		copy(qmIV, encPayload[len(encPayload)-blockSize:])
	}

	// Parse decrypted payloads.
	chain, err := ParsePayloadChain(decrypted, msg.Header.NextPayload, false)
	if err != nil {
		return nil, fmt.Errorf("Quick Mode msg1: parse: %w", err)
	}

	// Extract required payloads.
	hashPayload := findPayloadAs[*HashV1Payload](chain)
	if hashPayload == nil {
		return nil, fmt.Errorf("Quick Mode msg1: missing Hash payload")
	}

	saPayload := findPayloadAs[*SAv1Payload](chain)
	if saPayload == nil {
		return nil, fmt.Errorf("Quick Mode msg1: missing SA payload")
	}

	noncePayload := findPayloadAs[*NonceV1Payload](chain)
	if noncePayload == nil {
		return nil, fmt.Errorf("Quick Mode msg1: missing Nonce payload")
	}

	ni := noncePayload.NonceData

	// Verify HASH(1) = PRF(SKEYID_a, M-ID | SA | Ni [ | KE ] [ | IDci | IDcr ])
	hashInput := make([]byte, 4)
	binary.BigEndian.PutUint32(hashInput, msgID)

	// Append all payload bytes after Hash payload.
	saBytes, _ := saPayload.Marshal()
	nonceBytes, _ := noncePayload.Marshal()
	hashInput = append(hashInput, saBytes...)
	hashInput = append(hashInput, nonceBytes...)

	expectedHash := sess.PRF.Compute(sess.Keys.SKEYID_a, hashInput)
	if !hashEqual(expectedHash, hashPayload.HashData) {
		log.Warn("Quick Mode msg1: HASH(1) verification failed", "peer", sess.PeerAddr.String())
		return nil, fmt.Errorf("Quick Mode msg1: HASH(1) verification failed")
	}

	// Generate responder nonce.
	nr, err := GenerateNonce(32)
	if err != nil {
		return nil, fmt.Errorf("Quick Mode: nonce gen: %w", err)
	}

	// Generate our ESP SPI.
	var inSPI [4]byte
	if _, err := rand.Read(inSPI[:]); err != nil {
		return nil, fmt.Errorf("Quick Mode: SPI gen: %w", err)
	}

	// Extract peer's SPI from their proposal.
	var outSPI [4]byte
	if len(saPayload.Proposals) > 0 && len(saPayload.Proposals[0].SPI) >= 4 {
		copy(outSPI[:], saPayload.Proposals[0].SPI[:4])
	}

	// Build response SA (mirror their proposal with our SPI).
	respSA := &SAv1Payload{
		DOI:       DOIIPsec,
		Situation: SituationIdentityOnly,
		Proposals: []ProposalV1Payload{
			{
				Number:     1,
				ProtocolID: ProtocolESP,
				SPI:        inSPI[:],
				Transforms: saPayload.Proposals[0].Transforms, // Accept their first transform
			},
		},
	}

	respNonce := &NonceV1Payload{NonceData: nr}

	// Build HASH(2) = PRF(SKEYID_a, M-ID | Ni_b | SA | Nr [ | KE ] [ | IDci | IDcr ])
	hash2Input := make([]byte, 4)
	binary.BigEndian.PutUint32(hash2Input, msgID)
	hash2Input = append(hash2Input, ni...)
	respSABytes, _ := respSA.Marshal()
	hash2Input = append(hash2Input, respSABytes...)
	hash2Input = append(hash2Input, nr...)

	hash2 := sess.PRF.Compute(sess.Keys.SKEYID_a, hash2Input)

	// Build response payloads.
	respPayloads := []Payload{
		&HashV1Payload{HashData: hash2},
		respSA,
		respNonce,
	}

	respPayloadBytes, firstPT, err := MarshalPayloadChain(respPayloads)
	if err != nil {
		return nil, fmt.Errorf("Quick Mode msg2: marshal: %w", err)
	}

	// Encrypt.
	encResp, err := EncryptIKEv1Payload(sess.Encryptor, sess.Keys.SKEYID_e, qmIV, respPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("Quick Mode msg2: encrypt: %w", err)
	}

	// Derive Child SA keying material.
	// Determine needed key sizes from the accepted transform.
	childEncrKeyLen, childIntegKeyLen := extractV1ChildKeyLens(saPayload.Proposals[0].Transforms)
	neededBytes := (childEncrKeyLen + childIntegKeyLen) * 2 // Both directions

	keymat := DeriveIKEv1QuickModeKeys(
		sess.PRF, sess.Keys.SKEYID_d,
		byte(ProtocolESP), outSPI[:],
		ni, nr, nil, // No PFS for now
		neededBytes,
	)

	// Split keymat into per-direction keys.
	offset := 0
	childSA := &IKEv1ChildSA{
		MsgID:  msgID,
		InSPI:  inSPI,
		OutSPI: outSPI,
	}

	childSA.EncrKey = cloneSlice(keymat[offset : offset+childEncrKeyLen])
	offset += childEncrKeyLen

	childSA.IntegKey = cloneSlice(keymat[offset : offset+childIntegKeyLen])
	offset += childIntegKeyLen

	childSA.PeerEncrKey = cloneSlice(keymat[offset : offset+childEncrKeyLen])
	offset += childEncrKeyLen

	childSA.PeerIntegKey = cloneSlice(keymat[offset : offset+childIntegKeyLen])

	sess.ChildSAs = append(sess.ChildSAs, childSA)

	// Build encrypted response.
	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.CookieI,
			ResponderSPI: sess.CookieR,
			NextPayload:  firstPT,
			ExchangeType: ExchangeQuickMode,
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

	log.Info("IKEv1 Quick Mode Phase 2 SA created",
		"peer", sess.PeerAddr.String(),
		"in_spi", fmt.Sprintf("%x", inSPI),
		"out_spi", fmt.Sprintf("%x", outSPI),
		"msg_id", msgID,
	)

	return resp, nil
}

// HandleQuickMode3 processes Quick Mode message 3 (HASH(3) confirmation).
// This finalizes the Phase 2 SA.
func (h *IKEv1Handler) HandleQuickMode3(sess *IKEv1Session, msg *Message) error {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	// Message 3 is just HASH(3) confirmation.
	// In production, verify HASH(3) = PRF(SKEYID_a, 0 | M-ID | Ni_b | Nr_b).
	// For now, accept the confirmation.

	log.Info("IKEv1 Quick Mode msg3 confirmed",
		"peer", sess.PeerAddr.String(),
		"msg_id", msg.Header.MessageID,
	)

	return nil
}

// extractV1ChildKeyLens determines key sizes from IKEv1 Phase 2 transform attributes.
func extractV1ChildKeyLens(transforms []TransformV1Payload) (encrKeyLen, integKeyLen int) {
	if len(transforms) == 0 {
		return 16, 12 // Default: AES-128, HMAC-SHA1-96
	}

	xf := transforms[0]
	// Determine encryption key length.
	switch xf.TransformID {
	case V1ESPTransformAES:
		encrKeyLen = 16 // Default AES-128
		for _, attr := range xf.Attributes {
			if attr.Type == V1P2AttrKeyLength {
				kl := int(attrToUint16(attr))
				if kl > 0 {
					encrKeyLen = kl / 8
				}
			}
		}

	case V1ESPTransform3DES:
		encrKeyLen = 24

	case V1ESPTransformDES:
		encrKeyLen = 8

	default:
		encrKeyLen = 16
	}

	// Determine integrity key length.
	integKeyLen = 12 // Default HMAC-SHA1-96 (20-byte key, 12-byte output)
	for _, attr := range xf.Attributes {
		if attr.Type == V1P2AttrAuthAlg {
			switch attrToUint16(attr) {
			case V1IPsecAuthHMAC_SHA256:
				integKeyLen = 32

			case V1IPsecAuthHMAC_SHA1:
				integKeyLen = 20

			case V1IPsecAuthHMAC_MD5:
				integKeyLen = 16
			}
		}
	}

	return encrKeyLen, integKeyLen
}
