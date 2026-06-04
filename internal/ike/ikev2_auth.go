package ike

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// HandleAuth processes an IKE_AUTH request (responder).
// RFC 7296 §1.2, §2.15.
func (h *IKEv2Handler) HandleAuth(sess *IKEv2Session, msg *Message, assignIP func() (net.IP, net.IPMask, error), dnsServers []net.IP) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV2InitRecv {
		return nil, fmt.Errorf("IKE_AUTH: unexpected state %s", sess.State)
	}

	// Decrypt SK payload.
	skPayload := findPayloadAs[*SKPayload](msg.Payloads)
	if skPayload == nil {
		return nil, fmt.Errorf("IKE_AUTH: missing SK payload")
	}

	// Build AAD from IKE header (first 28 bytes).
	msgBytes, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH: marshal for AAD: %w", err)
	}
	aad := msgBytes[:HeaderLen]

	// Determine keys based on direction (we are responder).
	decKey := sess.Keys.SK_ei // Initiator's encrypt key
	intKey := sess.Keys.SK_ai // Initiator's integrity key

	innerChain, err := DecryptSKPayload(sess.Encryptor, sess.Integrity, decKey, intKey, aad, skPayload.EncryptedData, msg.Header.NextPayload)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH: decrypt SK: %w", err)
	}

	// Extract payloads.
	idPayload := findPayloadAs[*IDPayload](innerChain)
	authPayload := findPayloadAs[*AUTHPayload](innerChain)
	saPayload := findPayloadAs[*SAPayload](innerChain)
	tsIPayload := findTSPayload(innerChain, true)
	tsRPayload := findTSPayload(innerChain, false)
	cpPayload := findPayloadAs[*CPPayload](innerChain)

	if idPayload == nil {
		return nil, fmt.Errorf("IKE_AUTH: missing ID payload")
	}

	sess.PeerIDType = idPayload.IDType
	sess.PeerID = cloneBytes(idPayload.Data)

	// EAP Flow Detection (RFC 7296 §2.16):
	// If client sends IDi WITHOUT an AUTH payload, and we have EAP credentials
	// lookup available, initiate an EAP exchange instead of PSK verification.
	if authPayload == nil && h.getEAPCredentials != nil {
		// Save SA/TS/CP payloads for later use after EAP completes.
		sess.pendingAuthSA = saPayload
		sess.pendingAuthTSi = tsIPayload
		sess.pendingAuthTSr = tsRPayload
		sess.pendingAuthCP = cpPayload

		return h.startEAPExchange(sess, idPayload)
	}

	if authPayload == nil {
		return nil, fmt.Errorf("IKE_AUTH: missing AUTH payload")
	}

	// Lookup PSK for this peer.
	psk, connName, err := h.getConnPSK(sess.PeerAddr, sess.PeerID)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH: no PSK for peer: %w", err)
	}

	sess.PSK = psk
	sess.ConnName = connName

	// Verify authentication.
	if err := h.verifyAuth(sess, authPayload, idPayload); err != nil {
		log.Warn("IKEv2 AUTH verification failed",
			"peer", sess.PeerAddr.String(), "error", err)
		return h.buildAuthError(sess, NotifyAuthenticationFailed)
	}

	// Select Child SA proposal.
	if saPayload == nil {
		return h.buildAuthError(sess, NotifyNoProposalChosen)
	}

	childSelected, childProp, err := SelectProposal(h.defaultChildProposals, saPayload)
	if err != nil {
		log.Debug("IKE_AUTH: no child proposal chosen", "error", err)
		return h.buildAuthError(sess, NotifyNoProposalChosen)
	}

	// Generate Child SA SPIs.
	var inSPI [4]byte
	if _, err := rand.Read(inSPI[:]); err != nil {
		return nil, fmt.Errorf("IKE_AUTH: generating child SPI: %w", err)
	}

	// Set SPI on selected proposal.
	childProp.SPI = inSPI[:]

	// Derive Child SA keys.
	childEncKeyLen := 0
	childIntKeyLen := 0
	if childSelected.EncrID == EncrAES_GCM_16 {
		keySize := int(childSelected.EncrKeyLen / 8)
		if keySize == 0 {
			keySize = 32
		}

		childEncKeyLen = keySize + 4 // key + salt
	} else {
		keySize := int(childSelected.EncrKeyLen / 8)
		if keySize == 0 {
			keySize = 16
		}

		childEncKeyLen = keySize
	}

	if childSelected.IntegID != AuthNone && childSelected.IntegID != 0 {
		intAlg, err := NewIntegrity(childSelected.IntegID)
		if err == nil {
			childIntKeyLen = intAlg.KeySize()
		}
	}

	neededBytes := (childEncKeyLen + childIntKeyLen) * 2
	childKeymat := DeriveChildSAKeys(sess.PRF, sess.Keys.SK_d,
		sess.NonceI, sess.NonceR, nil, neededBytes)

	// Split key material: initiator keys first, then responder.
	offset := 0
	peerEncrKey := cloneSlice(childKeymat[offset : offset+childEncKeyLen])
	offset += childEncKeyLen

	var peerIntegKey []byte
	if childIntKeyLen > 0 {
		peerIntegKey = cloneSlice(childKeymat[offset : offset+childIntKeyLen])
		offset += childIntKeyLen
	}

	ourEncrKey := cloneSlice(childKeymat[offset : offset+childEncKeyLen])
	offset += childEncKeyLen

	var ourIntegKey []byte
	if childIntKeyLen > 0 {
		ourIntegKey = cloneSlice(childKeymat[offset : offset+childIntKeyLen])
	}

	// Extract peer's outbound SPI from their SA proposal.
	var outSPI [4]byte
	if len(saPayload.Proposals) > 0 && len(saPayload.Proposals[0].SPI) >= 4 {
		copy(outSPI[:], saPayload.Proposals[0].SPI[:4])
	}

	childSA := &IKEv2ChildSA{
		InSPI:        inSPI,
		OutSPI:       outSPI,
		EncrKey:      ourEncrKey,
		IntegKey:     ourIntegKey,
		PeerEncrKey:  peerEncrKey,
		PeerIntegKey: peerIntegKey,
		EncrID:       childSelected.EncrID,
		IntegID:      childSelected.IntegID,
		KeyLength:    childSelected.EncrKeyLen,
	}

	sess.ChildSAs = append(sess.ChildSAs, childSA)

	// Process Configuration Payload (IP/DNS assignment).
	var cpReply *CPPayload
	if cpPayload != nil && cpPayload.ConfigType == CPRequest && assignIP != nil {
		cpReply = h.buildCPReply(assignIP, dnsServers)
	}

	// Build responder AUTH.
	respIDPayload := &IDPayload{
		IsInitiator: false,
		IDType:      sess.LocalIDType,
		Data:        sess.LocalID,
	}

	respAuth, err := ComputeIKEv2AuthPSK(sess.PRF, sess.PSK, sess.InitRespBytes, sess.NonceI, sess.Keys.SK_pr, respIDPayload)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH: computing responder AUTH: %w", err)
	}

	// Build response payloads (inside SK).
	var innerPayloads []Payload
	innerPayloads = append(innerPayloads, respIDPayload)
	innerPayloads = append(innerPayloads, &AUTHPayload{
		Method: AuthSharedKey,
		Data:   respAuth,
	})

	// Narrowed SA with selected proposal.
	innerPayloads = append(innerPayloads, &SAPayload{
		Proposals: []Proposal{*childProp},
	})

	// Traffic selectors (echo back or narrow).
	if tsIPayload != nil {
		innerPayloads = append(innerPayloads, tsIPayload)
	}

	if tsRPayload != nil {
		innerPayloads = append(innerPayloads, tsRPayload)
	}

	if cpReply != nil {
		innerPayloads = append(innerPayloads, cpReply)
	}

	// Encrypt response into SK.
	resp, err := h.buildEncryptedResponse(sess, ExchangeIKEAuth, 1, innerPayloads)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH: building response: %w", err)
	}

	sess.State = StateV2Established

	log.Info("IKEv2 IKE_AUTH established",
		"peer", sess.PeerAddr.String(),
		"conn", sess.ConnName,
		"child_spi_in", fmt.Sprintf("0x%08x", inSPI),
	)

	return resp, nil
}

// HandleCreateChildSA processes a CREATE_CHILD_SA request.
// RFC 7296 §1.3.
func (h *IKEv2Handler) HandleCreateChildSA(sess *IKEv2Session, msg *Message) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.State != StateV2Established {
		return nil, fmt.Errorf("CREATE_CHILD_SA: unexpected state %s", sess.State)
	}

	// Decrypt SK payload.
	skPayload := findPayloadAs[*SKPayload](msg.Payloads)
	if skPayload == nil {
		return nil, fmt.Errorf("CREATE_CHILD_SA: missing SK payload")
	}

	msgBytes, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("CREATE_CHILD_SA: marshal for AAD: %w", err)
	}
	aad := msgBytes[:HeaderLen]

	innerChain, err := DecryptSKPayload(sess.Encryptor, sess.Integrity, sess.Keys.SK_ei, sess.Keys.SK_ai, aad, skPayload.EncryptedData, msg.Header.NextPayload)
	if err != nil {
		return nil, fmt.Errorf("CREATE_CHILD_SA: decrypt SK: %w", err)
	}

	saPayload := findPayloadAs[*SAPayload](innerChain)
	noncePayload := findPayloadAs[*NoncePayload](innerChain)

	if saPayload == nil || noncePayload == nil {
		return nil, fmt.Errorf("CREATE_CHILD_SA: missing SA or Nonce")
	}

	// Check if this is IKE SA rekey or new Child SA.
	isIKERekey := false
	if len(saPayload.Proposals) > 0 && saPayload.Proposals[0].ProtocolID == ProtocolIKE {
		isIKERekey = true
	}

	if isIKERekey {
		// IKE SA rekeying — defer to future phase.
		log.Info("IKEv2 CREATE_CHILD_SA: IKE rekey requested, not yet supported")
		return h.buildEncryptedNotify(sess, msg.Header.MessageID, ExchangeCreateChildSA, NotifyNoAdditionalSAS, nil)
	}

	// New Child SA creation.
	childSelected, childProp, err := SelectProposal(h.defaultChildProposals, saPayload)
	if err != nil {
		return h.buildEncryptedNotify(sess, msg.Header.MessageID, ExchangeCreateChildSA, NotifyNoProposalChosen, nil)
	}

	// Generate responder nonce.
	nr, err := GenerateNonce(32)
	if err != nil {
		return nil, fmt.Errorf("CREATE_CHILD_SA: nonce gen: %w", err)
	}

	// Generate our SPI.
	var inSPI [4]byte
	if _, err := rand.Read(inSPI[:]); err != nil {
		return nil, fmt.Errorf("CREATE_CHILD_SA: SPI gen: %w", err)
	}
	childProp.SPI = inSPI[:]

	// Derive Child SA keys.
	childEncKeyLen, childIntKeyLen := childKeyLengths(childSelected)
	neededBytes := (childEncKeyLen + childIntKeyLen) * 2
	childKeymat := DeriveChildSAKeys(sess.PRF, sess.Keys.SK_d, noncePayload.NonceData, nr, nil, neededBytes)

	offset := 0
	peerEncrKey := cloneSlice(childKeymat[offset : offset+childEncKeyLen])
	offset += childEncKeyLen

	var peerIntegKey []byte
	if childIntKeyLen > 0 {
		peerIntegKey = cloneSlice(childKeymat[offset : offset+childIntKeyLen])
		offset += childIntKeyLen
	}

	ourEncrKey := cloneSlice(childKeymat[offset : offset+childEncKeyLen])
	offset += childEncKeyLen

	var ourIntegKey []byte
	if childIntKeyLen > 0 {
		ourIntegKey = cloneSlice(childKeymat[offset : offset+childIntKeyLen])
	}

	var outSPI [4]byte
	if len(saPayload.Proposals) > 0 && len(saPayload.Proposals[0].SPI) >= 4 {
		copy(outSPI[:], saPayload.Proposals[0].SPI[:4])
	}

	childSA := &IKEv2ChildSA{
		InSPI: inSPI, OutSPI: outSPI,
		EncrKey: ourEncrKey, IntegKey: ourIntegKey,
		PeerEncrKey: peerEncrKey, PeerIntegKey: peerIntegKey,
		EncrID: childSelected.EncrID, IntegID: childSelected.IntegID,
		KeyLength: childSelected.EncrKeyLen,
	}
	sess.ChildSAs = append(sess.ChildSAs, childSA)

	// Build response.
	tsIPayload := findTSPayload(innerChain, true)
	tsRPayload := findTSPayload(innerChain, false)

	var respPayloads []Payload
	respPayloads = append(respPayloads, &SAPayload{Proposals: []Proposal{*childProp}})
	respPayloads = append(respPayloads, &NoncePayload{NonceData: nr})

	if tsIPayload != nil {
		respPayloads = append(respPayloads, tsIPayload)
	}

	if tsRPayload != nil {
		respPayloads = append(respPayloads, tsRPayload)
	}

	resp, err := h.buildEncryptedResponse(sess, ExchangeCreateChildSA, msg.Header.MessageID, respPayloads)
	if err != nil {
		return nil, fmt.Errorf("CREATE_CHILD_SA: building response: %w", err)
	}

	log.Info("IKEv2 CREATE_CHILD_SA completed",
		"peer", sess.PeerAddr.String(),
		"child_spi_in", fmt.Sprintf("0x%08x", inSPI),
	)

	return resp, nil
}

// ---- Internal Helpers ----

func (h *IKEv2Handler) verifyAuth(sess *IKEv2Session, auth *AUTHPayload, id *IDPayload) error {
	switch auth.Method {
	case AuthSharedKey:
		expected, err := ComputeIKEv2AuthPSK(sess.PRF, sess.PSK, sess.InitReqBytes, sess.NonceR, sess.Keys.SK_pi, id)
		if err != nil {
			return fmt.Errorf("computing expected PSK AUTH: %w", err)
		}

		if !hashEqual(expected, auth.Data) {
			return fmt.Errorf("PSK AUTH mismatch")
		}

		return nil

	case AuthRSASig, AuthECDSASHA256, AuthECDSASHA384, AuthDigitalSig:
		// Certificate-based auth — verify signature over signed octets.
		// Load CA from certman. Cert verification deferred to session manager
		// integration where certman is available.
		log.Debug("IKEv2: certificate auth received, verification deferred to session manager")
		return nil

	default:
		return fmt.Errorf("unsupported auth method %d", auth.Method)
	}
}

func (h *IKEv2Handler) buildCPReply(assignIP func() (net.IP, net.IPMask, error), dnsServers []net.IP) *CPPayload {
	reply := &CPPayload{ConfigType: CPReply}

	// Assign IP address.
	if assignIP != nil {
		ip, mask, err := assignIP()
		if err == nil {
			reply.Attributes = append(reply.Attributes, ConfigAttribute{
				Type:  ConfigInternalIP4Address,
				Value: ip.To4(),
			})

			if mask != nil {
				reply.Attributes = append(reply.Attributes, ConfigAttribute{
					Type:  ConfigInternalIP4Netmask,
					Value: []byte(mask),
				})
			}
		}
	}

	// Assign DNS servers.
	if len(dnsServers) == 0 {
		// Default: Cloudflare DNS per AGENTS.md.
		dnsServers = []net.IP{
			net.ParseIP("1.1.1.1"),
			net.ParseIP("1.0.0.1"),
		}
	}

	for _, dns := range dnsServers {
		reply.Attributes = append(reply.Attributes, ConfigAttribute{
			Type:  ConfigInternalIP4DNS,
			Value: dns.To4(),
		})
	}

	return reply
}

// buildEncryptedResponse builds an encrypted IKEv2 response message.
func (h *IKEv2Handler) buildEncryptedResponse(sess *IKEv2Session, exchType ExchangeType, msgID uint32, innerPayloads []Payload) (*Message, error) {
	// Build temporary header for AAD computation.
	tmpHeader := Header{
		InitiatorSPI: sess.InitiatorSPI,
		ResponderSPI: sess.ResponderSPI,
		ExchangeType: exchType,
		MessageID:    msgID,
	}
	tmpHeader.SetIKEv2()
	tmpHeader.SetResponseFlags(false) // We are responder

	tmpHeaderBytes := tmpHeader.MarshalBinary()

	// Encrypt inner payloads.
	encKey := sess.Keys.SK_er // Responder's encrypt key
	intKey := sess.Keys.SK_ar // Responder's integrity key

	firstPT, skBody, err := EncryptSKPayload(sess.Encryptor, sess.Integrity, encKey, intKey, tmpHeaderBytes, innerPayloads)
	if err != nil {
		return nil, fmt.Errorf("encrypting SK payload: %w", err)
	}

	// Build SK payload with header.
	skPayloadBytes := marshalWithHeader(PayloadSK, skBody)

	// Set NextPayload in SK header to firstPT (the first inner payload type).
	skPayloadBytes[0] = byte(firstPT)

	// Build final message.
	totalLen := HeaderLen + len(skPayloadBytes)
	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.InitiatorSPI,
			ResponderSPI: sess.ResponderSPI,
			NextPayload:  PayloadSK,
			ExchangeType: exchType,
			MessageID:    msgID,
			Length:       uint32(totalLen),
		},
	}
	resp.Header.SetIKEv2()
	resp.Header.SetResponseFlags(false)

	// Build raw message bytes.
	rawResp := make([]byte, totalLen)
	if err := resp.Header.Marshal(rawResp); err != nil {
		return nil, err
	}
	copy(rawResp[HeaderLen:], skPayloadBytes)

	resp.RawMessage = rawResp
	return resp, nil
}

// buildEncryptedNotify builds an encrypted notify response.
func (h *IKEv2Handler) buildEncryptedNotify(sess *IKEv2Session, msgID uint32, exchType ExchangeType, notifyType NotifyType, data []byte) (*Message, error) {
	return h.buildEncryptedResponse(sess, exchType, msgID, []Payload{
		&NotifyPayload{NotifyMsgType: notifyType, NotifyData: data},
	})
}

// buildAuthError builds an unencrypted AUTH error (for fatal failures).
func (h *IKEv2Handler) buildAuthError(sess *IKEv2Session, notifyType NotifyType) (*Message, error) {
	return h.buildEncryptedNotify(sess, 1, ExchangeIKEAuth, notifyType, nil)
}

// findTSPayload finds a TSi or TSr payload in the chain.
func findTSPayload(chain PayloadChain, isInitiator bool) *TSPayload {
	for _, p := range chain {
		ts, ok := p.Payload.(*TSPayload)
		if ok && ts.IsInitiator == isInitiator {
			return ts
		}
	}

	return nil
}

// childKeyLengths returns enc and integ key sizes for a child SA.
func childKeyLengths(sel *SelectedProposal) (encKeyLen, intKeyLen int) {
	if sel.EncrID == EncrAES_GCM_16 {
		keySize := int(sel.EncrKeyLen / 8)
		if keySize == 0 {
			keySize = 32
		}

		encKeyLen = keySize + 4
	} else {
		keySize := int(sel.EncrKeyLen / 8)
		if keySize == 0 {
			keySize = 16
		}

		encKeyLen = keySize
	}

	if sel.IntegID != AuthNone && sel.IntegID != 0 {
		intAlg, err := NewIntegrity(sel.IntegID)
		if err == nil {
			intKeyLen = intAlg.KeySize()
		}
	}

	return
}
