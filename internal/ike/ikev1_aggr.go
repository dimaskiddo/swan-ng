package ike

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// HandleAggressive1 processes Aggressive Mode message 1 from initiator.
// Returns message 2 (SA + KE + Nonce + ID + Hash_R) and new session.
// RFC 2409 §5.3.
func (h *IKEv1Handler) HandleAggressive1(msg *Message, peerAddr *net.UDPAddr) (*Message, *IKEv1Session, error) {
	// Extract SA, KE, Nonce, ID payloads.
	saPayload := findPayloadAs[*SAv1Payload](msg.Payloads)
	if saPayload == nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: missing SA payload")
	}

	kePayload := findPayloadAs[*KEv1Payload](msg.Payloads)
	if kePayload == nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: missing KE payload")
	}

	noncePayload := findPayloadAs[*NonceV1Payload](msg.Payloads)
	if noncePayload == nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: missing Nonce payload")
	}

	idPayload := findPayloadAs[*IDv1Payload](msg.Payloads)
	if idPayload == nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: missing ID payload")
	}

	// Select proposal.
	matched, _, matchedXf, err := SelectV1Proposal(saPayload, h.supportedP1)
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: %w", err)
	}

	// Lookup PSK.
	psk, connName, err := h.getConnPSK(peerAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: no PSK for %s: %w", peerAddr, err)
	}

	// Generate responder cookie.
	var cookieR [8]byte
	if _, err := rand.Read(cookieR[:]); err != nil {
		return nil, nil, fmt.Errorf("generating responder cookie: %w", err)
	}

	// Initialize PRF.
	prfID := v1HashToPRF(matched.HashAlg)
	prf, err := NewPRF(prfID)
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: PRF: %w", err)
	}

	// DH key exchange.
	dh, err := NewDHGroup(matched.DHGroup)
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: DH: %w", err)
	}

	privKey, pubKey, err := dh.GenerateKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: DH keygen: %w", err)
	}

	shared, err := dh.ComputeSharedSecret(privKey, kePayload.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: DH shared: %w", err)
	}

	// Generate nonce.
	nr, err := GenerateNonce(32)
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: nonce: %w", err)
	}

	// Derive keys.
	keys, err := DeriveIKEv1Keys(prf, psk, shared, noncePayload.NonceData, nr, msg.Header.InitiatorSPI, cookieR)
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: key derivation: %w", err)
	}

	// Initialize encryptor.
	enc, err := NewIKEEncryptor(v1EncToV2Enc(matched.EncAlg), matched.KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("Aggressive msg1: encryptor: %w", err)
	}

	encrKeyLen := v1EncKeySize(matched.EncAlg, matched.KeyLength)
	skeyidE := expandV1EncKey(prf, keys.SKEYID_e, encrKeyLen)
	keys.SKEYID_e = skeyidE

	// Create session.
	sess := &IKEv1Session{
		CookieI:      msg.Header.InitiatorSPI,
		CookieR:      cookieR,
		State:        StateV1AggrRecv,
		EncAlg:       matched.EncAlg,
		HashAlg:      matched.HashAlg,
		AuthMethod:   matched.AuthMethod,
		DHGroupID:    matched.DHGroup,
		KeyLength:    matched.KeyLength,
		DHPrivKey:    privKey,
		DHPubKey:     pubKey,
		PeerDHPubKey: kePayload.Data,
		SharedSecret: shared,
		NonceI:       noncePayload.NonceData,
		NonceR:       nr,
		Keys:         keys,
		PRF:          prf,
		Encryptor:    enc,
		PeerAddr:     peerAddr,
		PeerID:       idPayload.Data,
		LocalID:      h.localID,
		PSK:          psk,
		ConnName:     connName,
	}

	sess.CurrentIV = computeV1InitialIV(matched.HashAlg,
		noncePayload.NonceData, nr, enc)

	// Compute HASH_R.
	localIDPayload := &IDv1Payload{IDType: h.localIDType, Data: h.localID}
	hashR := h.computeV1Hash(sess, false, localIDPayload)

	// Build response SA.
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

	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.CookieI,
			ResponderSPI: sess.CookieR,
			ExchangeType: ExchangeAggressive,
		},
	}

	resp.Header.SetIKEv1()

	resp.Payloads = PayloadChain{
		{Payload: respSA},
		{Payload: &KEv1Payload{Data: pubKey}},
		{Payload: &NonceV1Payload{NonceData: nr}},
		{Payload: localIDPayload},
		{Payload: &HashV1Payload{HashData: hashR}},
	}

	log.Info("IKEv1 Aggressive Mode msg1 processed",
		"peer", peerAddr.String(),
		"conn", connName,
	)

	return resp, sess, nil
}

// HandleAggressive3 processes Aggressive Mode message 3 (Hash from initiator).
// Verifies HASH_I and completes Phase 1.
func (h *IKEv1Handler) HandleAggressive3(sess *IKEv1Session, msg *Message) error {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV1AggrRecv {
		return fmt.Errorf("Aggressive msg3: unexpected state %s", sess.State)
	}

	hashPayload := findPayloadAs[*HashV1Payload](msg.Payloads)
	if hashPayload == nil {
		return fmt.Errorf("Aggressive msg3: missing Hash payload")
	}

	// Verify HASH_I.
	peerIDPayload := &IDv1Payload{IDType: IDIPv4Addr, Data: sess.PeerID}
	expectedHash := h.computeV1Hash(sess, true, peerIDPayload)
	if !hashEqual(expectedHash, hashPayload.HashData) {
		return fmt.Errorf("Aggressive msg3: HASH_I verification failed")
	}

	sess.State = StateV1Established

	log.Info("IKEv1 Aggressive Mode Phase 1 established",
		"peer", sess.PeerAddr.String(),
		"conn", sess.ConnName,
	)

	return nil
}

// ---- IKEv1 Mode Config (ISAKMP Config Mode / XAUTH) ----

// IKEv1 Mode Config message types (draft-ietf-ipsec-isakmp-mode-cfg).
const (
	ModeConfigRequest uint8 = 1
	ModeConfigReply   uint8 = 2
	ModeConfigSet     uint8 = 3
	ModeConfigAck     uint8 = 4
)

// ModeConfigPayload represents the IKEv1 Mode Config (Attribute) payload.
// Used for IP address assignment (Mode Config / XAUTH).
type ModeConfigPayload struct {
	ConfigType uint8
	Identifier uint16
	Attributes []ISAKMPAttribute
}

func (p *ModeConfigPayload) Type() PayloadType { return PayloadType(14) } // ISAKMP_CFG

func (p *ModeConfigPayload) Marshal() ([]byte, error) {
	var attrBytes []byte
	for _, attr := range p.Attributes {
		attrBytes = append(attrBytes, attr.Marshal()...)
	}

	body := make([]byte, 4+len(attrBytes))
	body[0] = p.ConfigType

	// body[1] reserved

	body[2] = byte(p.Identifier >> 8)
	body[3] = byte(p.Identifier)

	copy(body[4:], attrBytes)

	return marshalWithHeader(p.Type(), body), nil
}

// Mode Config attribute types.
const (
	MCAttrInternalIP4     uint16 = 1
	MCAttrInternalIP4Mask uint16 = 2
	MCAttrInternalIP4DNS  uint16 = 3
	MCAttrInternalIP4NBNS uint16 = 4
	MCAttrAppVersion      uint16 = 7
	MCAttrInternalIP4Sub  uint16 = 13
)

// HandleModeConfig processes a Mode Config request within an established Phase 1.
// Assigns IP address and DNS from the IPAM pool.
func (h *IKEv1Handler) HandleModeConfig(sess *IKEv1Session, msg *Message, assignIP func() (net.IP, net.IPMask, error), dnsServers []net.IP) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV1Established {
		return nil, fmt.Errorf("Mode Config: Phase 1 not established")
	}

	msgID := msg.Header.MessageID

	// Decrypt message.
	blockSize := 16
	if sess.Encryptor != nil {
		blockSize = sess.Encryptor.BlockSize()
	}

	qmIV := ComputeV1QuickModeIV(sess.HashAlg, sess.CurrentIV, msgID, blockSize)

	msgBytes, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("Mode Config: marshal: %w", err)
	}

	encPayload := msgBytes[HeaderLen:]
	decrypted, err := DecryptIKEv1Payload(sess.Encryptor, sess.Keys.SKEYID_e, qmIV, encPayload)
	if err != nil {
		return nil, fmt.Errorf("Mode Config: decrypt: %w", err)
	}

	if len(encPayload) >= blockSize {
		qmIV = make([]byte, blockSize)
		copy(qmIV, encPayload[len(encPayload)-blockSize:])
	}

	// Parse decrypted payloads.
	chain, err := ParsePayloadChain(decrypted, msg.Header.NextPayload, false)
	if err != nil {
		return nil, fmt.Errorf("Mode Config: parse: %w", err)
	}

	// Find Hash + Config payloads.
	_ = findPayloadAs[*HashV1Payload](chain)
	// Config payload might be parsed as raw if we haven't registered type 14.
	// Find raw payload with type 14.
	var configReq *ModeConfigPayload
	for _, pp := range chain {
		if raw, ok := pp.Payload.(*RawPayload); ok && raw.PayloadType == PayloadType(14) {
			if len(raw.Data) >= 4 {
				configReq = &ModeConfigPayload{
					ConfigType: raw.Data[0],
					Identifier: uint16(raw.Data[2])<<8 | uint16(raw.Data[3]),
					Attributes: ParseISAKMPAttributes(raw.Data[4:]),
				}
			}
		}
	}

	if configReq == nil || configReq.ConfigType != ModeConfigRequest {
		return nil, fmt.Errorf("Mode Config: not a config request")
	}

	// Assign IP.
	ip, mask, err := assignIP()
	if err != nil {
		return nil, fmt.Errorf("Mode Config: IPAM: %w", err)
	}

	// Default DNS: 1.1.1.1 and 1.0.0.1 per AGENTS.md.
	if len(dnsServers) == 0 {
		dnsServers = []net.IP{
			net.ParseIP("1.1.1.1").To4(),
			net.ParseIP("1.0.0.1").To4(),
		}
	}

	// Build reply attributes.
	var replyAttrs []ISAKMPAttribute
	replyAttrs = append(replyAttrs, ISAKMPAttribute{
		Type: MCAttrInternalIP4, IsTV: false,
		Value: ip.To4(),
	})

	replyAttrs = append(replyAttrs, ISAKMPAttribute{
		Type: MCAttrInternalIP4Mask, IsTV: false,
		Value: []byte(mask),
	})

	for _, dns := range dnsServers {
		replyAttrs = append(replyAttrs, ISAKMPAttribute{
			Type: MCAttrInternalIP4DNS, IsTV: false,
			Value: dns.To4(),
		})
	}

	configReply := &ModeConfigPayload{
		ConfigType: ModeConfigReply,
		Identifier: configReq.Identifier,
		Attributes: replyAttrs,
	}

	// Build Hash for response.
	hashInput := make([]byte, 4)
	binary.BigEndian.PutUint32(hashInput, msgID)
	cfgBytes, _ := configReply.Marshal()
	hashInput = append(hashInput, cfgBytes...)
	respHash := sess.PRF.Compute(sess.Keys.SKEYID_a, hashInput)

	// Marshal and encrypt.
	respPayloads := []Payload{
		&HashV1Payload{HashData: respHash},
		configReply,
	}

	respPayloadBytes, firstPT, err := MarshalPayloadChain(respPayloads)
	if err != nil {
		return nil, fmt.Errorf("Mode Config: marshal reply: %w", err)
	}

	encResp, err := EncryptIKEv1Payload(sess.Encryptor, sess.Keys.SKEYID_e, qmIV, respPayloadBytes)
	if err != nil {
		return nil, fmt.Errorf("Mode Config: encrypt reply: %w", err)
	}

	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.CookieI,
			ResponderSPI: sess.CookieR,
			NextPayload:  firstPT,
			ExchangeType: ExchangeInformationalV1,
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

	log.Info("IKEv1 Mode Config: assigned IP",
		"peer", sess.PeerAddr.String(),
		"ip", ip.String(),
	)

	return resp, nil
}
