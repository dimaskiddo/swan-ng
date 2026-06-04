package ike

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"net"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// IKEv1Handler handles IKEv1 exchanges (responder).
type IKEv1Handler struct {
	supportedP1 []V1Phase1Config
	getConnPSK  func(peerAddr *net.UDPAddr) (psk []byte, connName string, err error)
	localID     []byte
	localIDType IDType
}

// NewIKEv1Handler creates a new IKEv1 exchange handler.
func NewIKEv1Handler(
	getConnPSK func(peerAddr *net.UDPAddr) ([]byte, string, error),
	localID []byte,
	localIDType IDType,
) *IKEv1Handler {
	return &IKEv1Handler{
		supportedP1: DefaultV1Phase1Configs(),
		getConnPSK:  getConnPSK,
		localID:     localID,
		localIDType: localIDType,
	}
}

// HandleMainMode1 processes Main Mode message 1 (SA proposal from initiator).
// Returns response message 2 (selected SA) and a new session.
func (h *IKEv1Handler) HandleMainMode1(
	msg *Message, peerAddr *net.UDPAddr,
) (*Message, *IKEv1Session, error) {
	// Extract SA payload.
	saPayload := findPayloadAs[*SAv1Payload](msg.Payloads)
	if saPayload == nil {
		return nil, nil, fmt.Errorf("Main Mode msg1: missing SA payload")
	}

	// Select proposal.
	matched, _, matchedXf, err := SelectV1Proposal(saPayload, h.supportedP1)
	if err != nil {
		return nil, nil, fmt.Errorf("Main Mode msg1: %w", err)
	}

	// Lookup PSK for this peer.
	psk, connName, err := h.getConnPSK(peerAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("Main Mode msg1: no PSK for peer %s: %w", peerAddr, err)
	}

	// Generate responder cookie.
	var cookieR [8]byte
	if _, err := rand.Read(cookieR[:]); err != nil {
		return nil, nil, fmt.Errorf("generating responder cookie: %w", err)
	}

	// Create session.
	sess := &IKEv1Session{
		CookieI:    msg.Header.InitiatorSPI,
		CookieR:    cookieR,
		State:      StateV1MainSARecv,
		EncAlg:     matched.EncAlg,
		HashAlg:    matched.HashAlg,
		AuthMethod: matched.AuthMethod,
		DHGroupID:  matched.DHGroup,
		KeyLength:  matched.KeyLength,
		PeerAddr:   peerAddr,
		PSK:        psk,
		ConnName:   connName,
		LocalID:    h.localID,
	}

	// Initialize PRF from hash algorithm.
	prfID := v1HashToPRF(matched.HashAlg)
	sess.PRF, err = NewPRF(prfID)
	if err != nil {
		return nil, nil, fmt.Errorf("creating PRF for hash %d: %w", matched.HashAlg, err)
	}

	// Build response SA with selected transform.
	respSA := &SAv1Payload{
		DOI:       DOIIPsec,
		Situation: SituationIdentityOnly,
		Proposals: []ProposalV1Payload{
			{
				Number:     1,
				ProtocolID: ProtocolIKE,
				Transforms: []TransformV1Payload{*matchedXf},
			},
		},
	}

	// Build response message.
	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.CookieI,
			ResponderSPI: sess.CookieR,
			ExchangeType: ExchangeIdentityProtect,
			Flags:        0, // No flags for IKEv1 response (no R bit)
		},
	}
	resp.Header.SetIKEv1()
	resp.Payloads = PayloadChain{
		{Payload: respSA},
	}

	log.Info("IKEv1 Main Mode msg1 processed",
		"peer", peerAddr.String(),
		"encr", matched.EncAlg,
		"hash", matched.HashAlg,
		"dh", matched.DHGroup,
		"conn", connName,
	)

	return resp, sess, nil
}

// HandleMainMode3 processes Main Mode message 3 (KE + Nonce from initiator).
// Returns response message 4 (our KE + Nonce).
func (h *IKEv1Handler) HandleMainMode3(
	sess *IKEv1Session, msg *Message,
) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV1MainSARecv {
		return nil, fmt.Errorf("Main Mode msg3: unexpected state %s", sess.State)
	}

	// Extract KE payload.
	kePayload := findPayloadAs[*KEv1Payload](msg.Payloads)
	if kePayload == nil {
		return nil, fmt.Errorf("Main Mode msg3: missing KE payload")
	}

	// Extract Nonce payload.
	noncePayload := findPayloadAs[*NonceV1Payload](msg.Payloads)
	if noncePayload == nil {
		return nil, fmt.Errorf("Main Mode msg3: missing Nonce payload")
	}

	sess.PeerDHPubKey = kePayload.Data
	sess.NonceI = noncePayload.NonceData

	// Generate our DH keypair.
	dh, err := NewDHGroup(sess.DHGroupID)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg3: DH group %d: %w", sess.DHGroupID, err)
	}

	sess.DHPrivKey, sess.DHPubKey, err = dh.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg3: DH keygen: %w", err)
	}

	// Compute shared secret.
	sess.SharedSecret, err = dh.ComputeSharedSecret(sess.DHPrivKey, sess.PeerDHPubKey)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg3: DH shared secret: %w", err)
	}

	// Generate responder nonce.
	sess.NonceR, err = GenerateNonce(32)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg3: nonce gen: %w", err)
	}

	// Derive keys.
	sess.Keys, err = DeriveIKEv1Keys(sess.PRF, sess.PSK, sess.SharedSecret,
		sess.NonceI, sess.NonceR, sess.CookieI, sess.CookieR)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg3: key derivation: %w", err)
	}

	// Compute initial IV: hash(Ni || Nr) truncated to block size.
	sess.CurrentIV = computeV1InitialIV(sess.HashAlg, sess.NonceI, sess.NonceR, sess.Encryptor)

	// Initialize encryptor.
	encrKeyLen := v1EncKeySize(sess.EncAlg, sess.KeyLength)
	sess.Encryptor, err = NewIKEEncryptor(v1EncToV2Enc(sess.EncAlg), sess.KeyLength)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg3: encryptor: %w", err)
	}

	// Expand SKEYID_e if needed (RFC 2409 Appendix B).
	sess.Keys.SKEYID_e = expandV1EncKey(sess.PRF, sess.Keys.SKEYID_e, encrKeyLen)

	// Recompute IV now that encryptor is initialized.
	sess.CurrentIV = computeV1InitialIV(sess.HashAlg, sess.NonceI, sess.NonceR, sess.Encryptor)

	sess.State = StateV1MainKERecv

	// Build response: KE + Nonce.
	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.CookieI,
			ResponderSPI: sess.CookieR,
			ExchangeType: ExchangeIdentityProtect,
		},
	}
	resp.Header.SetIKEv1()
	resp.Payloads = PayloadChain{
		{Payload: &KEv1Payload{Data: sess.DHPubKey}},
		{Payload: &NonceV1Payload{NonceData: sess.NonceR}},
	}

	log.Debug("IKEv1 Main Mode msg3 processed", "peer", sess.PeerAddr.String())
	return resp, nil
}

// HandleMainMode5 processes Main Mode message 5 (encrypted ID + Hash from initiator).
// Returns response message 6 (our encrypted ID + Hash).
func (h *IKEv1Handler) HandleMainMode5(
	sess *IKEv1Session, msg *Message,
) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV1MainKERecv {
		return nil, fmt.Errorf("Main Mode msg5: unexpected state %s", sess.State)
	}

	// Message 5 is encrypted. Decrypt the payload body.
	if !msg.Header.IsEncrypted() {
		return nil, fmt.Errorf("Main Mode msg5: expected encrypted message")
	}

	msgBytes, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg5: re-marshal failed: %w", err)
	}

	// Decrypt payload portion (everything after header).
	encPayload := msgBytes[HeaderLen:]
	decrypted, err := DecryptIKEv1Payload(sess.Encryptor, sess.Keys.SKEYID_e,
		sess.CurrentIV, encPayload)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg5: decrypt: %w", err)
	}

	// Update IV to last ciphertext block.
	blockSize := sess.Encryptor.BlockSize()
	if len(encPayload) >= blockSize {
		sess.CurrentIV = make([]byte, blockSize)
		copy(sess.CurrentIV, encPayload[len(encPayload)-blockSize:])
	}

	// Parse decrypted payloads.
	chain, err := ParsePayloadChain(decrypted, msg.Header.NextPayload, false)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg5: parse decrypted payloads: %w", err)
	}

	// Extract ID and Hash.
	idPayload := findPayloadInChain[*IDv1Payload](chain)
	if idPayload == nil {
		return nil, fmt.Errorf("Main Mode msg5: missing ID payload")
	}
	hashPayload := findPayloadInChain[*HashV1Payload](chain)
	if hashPayload == nil {
		return nil, fmt.Errorf("Main Mode msg5: missing Hash payload")
	}

	sess.PeerID = idPayload.Data

	// Verify initiator's hash (RFC 2409 §5.1):
	// HASH_I = PRF(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)
	expectedHash := h.computeV1Hash(sess, true, idPayload)
	if !hashEqual(expectedHash, hashPayload.HashData) {
		return nil, fmt.Errorf("Main Mode msg5: hash verification failed")
	}

	// Build our ID payload.
	localIDPayload := &IDv1Payload{
		IDType: h.localIDType,
		Data:   sess.LocalID,
	}

	// Compute responder hash:
	// HASH_R = PRF(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)
	respHash := h.computeV1Hash(sess, false, localIDPayload)

	// Build plaintext response: ID + Hash.
	respPayloads := []Payload{
		localIDPayload,
		&HashV1Payload{HashData: respHash},
	}

	respPayloadBytes, firstPT, err := MarshalPayloadChain(respPayloads)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg5: marshal response payloads: %w", err)
	}

	// Encrypt response.
	encResp, err := EncryptIKEv1Payload(sess.Encryptor, sess.Keys.SKEYID_e,
		sess.CurrentIV, respPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("Main Mode msg5: encrypt response: %w", err)
	}

	// Update IV.
	if len(encResp) >= blockSize {
		sess.CurrentIV = make([]byte, blockSize)
		copy(sess.CurrentIV, encResp[len(encResp)-blockSize:])
	}

	// Build response header.
	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.CookieI,
			ResponderSPI: sess.CookieR,
			NextPayload:  firstPT,
			ExchangeType: ExchangeIdentityProtect,
			Flags:        FlagV1Encryption,
			Length:       uint32(HeaderLen + len(encResp)),
		},
	}
	resp.Header.SetIKEv1()

	// Manually build the encrypted message.
	rawResp := make([]byte, HeaderLen+len(encResp))
	if err := resp.Header.Marshal(rawResp); err != nil {
		return nil, err
	}
	copy(rawResp[HeaderLen:], encResp)

	sess.State = StateV1Established

	log.Info("IKEv1 Main Mode Phase 1 established",
		"peer", sess.PeerAddr.String(),
		"conn", sess.ConnName,
	)

	// Return a special message with pre-marshaled bytes.
	return &Message{
		Header:     resp.Header,
		RawMessage: rawResp,
	}, nil
}

// computeV1Hash computes the IKEv1 Phase 1 HASH_I or HASH_R.
// RFC 2409 §5.1 (Main Mode PSK):
//
//	HASH_I = PRF(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)
//	HASH_R = PRF(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b)
func (h *IKEv1Handler) computeV1Hash(
	sess *IKEv1Session, isInitiator bool, idPayload *IDv1Payload,
) []byte {
	idBytes, _ := idPayload.Marshal()
	// Strip the generic payload header to get IDii_b / IDir_b.
	idBody := idBytes
	if len(idBytes) > PayloadHeaderLen {
		idBody = idBytes[PayloadHeaderLen:]
	}

	var input []byte
	if isInitiator {
		input = append(input, sess.PeerDHPubKey...) // g^xi (initiator's KE)
		input = append(input, sess.DHPubKey...)     // g^xr (our KE)
		input = append(input, sess.CookieI[:]...)
		input = append(input, sess.CookieR[:]...)
	} else {
		input = append(input, sess.DHPubKey...)     // g^xr (our KE)
		input = append(input, sess.PeerDHPubKey...) // g^xi (initiator's KE)
		input = append(input, sess.CookieR[:]...)
		input = append(input, sess.CookieI[:]...)
	}
	// SAi_b is omitted in simplified PSK mode per common implementations.
	input = append(input, idBody...)

	return sess.PRF.Compute(sess.Keys.SKEYID, input)
}

// ---- Utilities ----

// findPayloadAs finds the first payload of type T in a PayloadChain.
func findPayloadAs[T Payload](chain PayloadChain) T {
	for _, pp := range chain {
		if typed, ok := pp.Payload.(T); ok {
			return typed
		}
	}
	var zero T
	return zero
}

// findPayloadInChain finds first payload of type T in a flat PayloadChain.
func findPayloadInChain[T Payload](chain PayloadChain) T {
	return findPayloadAs[T](chain)
}

func hashEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func v1HashToPRF(hashAlg uint16) uint16 {
	switch hashAlg {
	case V1HashSHA1:
		return PRFHMAC_SHA1

	case V1HashSHA256:
		return PRFHMAC_SHA256

	case V1HashSHA384:
		return PRFHMAC_SHA384

	case V1HashSHA512:
		return PRFHMAC_SHA512

	default:
		return PRFHMAC_SHA1
	}
}

func v1EncToV2Enc(encAlg uint16) uint16 {
	switch encAlg {
	case V1EncrAES_CBC:
		return EncrAES_CBC

	case V1Encr3DES_CBC:
		return Encr3DES

	default:
		return EncrAES_CBC
	}
}

func v1EncKeySize(encAlg uint16, keyLength uint16) int {
	if keyLength > 0 {
		return int(keyLength / 8)
	}

	switch encAlg {
	case V1EncrAES_CBC:
		return 16

	case V1Encr3DES_CBC:
		return 24

	case V1EncrDES_CBC:
		return 8

	default:
		return 16
	}
}

// expandV1EncKey expands SKEYID_e to the required key length per RFC 2409 Appendix B.
func expandV1EncKey(prf PRFAlgorithm, skeyidE []byte, needed int) []byte {
	if len(skeyidE) >= needed {
		return skeyidE[:needed]
	}

	// Expand: K1 = PRF(SKEYID_e, 0x00), K2 = PRF(SKEYID_e, K1), ...
	var expanded []byte
	prev := []byte{0}
	for len(expanded) < needed {
		prev = prf.Compute(skeyidE, prev)
		expanded = append(expanded, prev...)
	}

	return expanded[:needed]
}

// computeV1InitialIV computes the initial IV for IKEv1 encrypted messages.
// IV = hash(g^xi | g^xr)[0:blockSize]
func computeV1InitialIV(hashAlg uint16, ni, nr []byte, enc IKEEncryptor) []byte {
	var hashFunc func() hash.Hash
	switch hashAlg {
	case V1HashSHA256:
		hashFunc = sha256.New

	default:
		hashFunc = sha1.New
	}

	h := hashFunc()
	h.Write(ni)
	h.Write(nr)
	full := h.Sum(nil)

	blockSize := 16 // Default AES block size
	if enc != nil {
		blockSize = enc.BlockSize()
	}

	if len(full) < blockSize {
		return full
	}

	return full[:blockSize]
}

// ComputeV1QuickModeIV computes the IV for a Quick Mode exchange.
// IV = hash(Phase1_IV | MessageID)
func ComputeV1QuickModeIV(hashAlg uint16, phase1IV []byte, msgID uint32, blockSize int) []byte {
	var hashFunc func() hash.Hash
	switch hashAlg {
	case V1HashSHA256:
		hashFunc = sha256.New

	default:
		hashFunc = sha1.New
	}

	h := hashFunc()
	h.Write(phase1IV)
	msgIDBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(msgIDBuf, msgID)
	h.Write(msgIDBuf)
	full := h.Sum(nil)

	if len(full) < blockSize {
		return full
	}

	return full[:blockSize]
}
