package ike

import (
	"crypto/rand"
	"fmt"
	"net"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// startEAPExchange initiates an EAP authentication exchange.
// Called from HandleAuth when client sends IDi without AUTH payload.
// RFC 7296 §2.16: Responder sends EAP-Identity request as first EAP message.
//
// The first IKE_AUTH response contains:
//   - IDr (responder identity)
//   - [CERT] (optional)
//   - AUTH (responder signs with server key — for EAP, this is deferred or server-cert based)
//   - EAP (EAP-Identity Request)
//
// Note: Per RFC 7296 §2.16, the responder MUST NOT include AUTH payload
// in the first EAP response. The responder sends AUTH only in the final
// IKE_AUTH response after EAP-Success.
func (h *IKEv2Handler) startEAPExchange(sess *IKEv2Session, _ *IDPayload) (*Message, error) {
	sess.EAPIdentifier = 1
	sess.State = StateV2EAPInProgress

	log.Info("IKEv2 EAP exchange initiated",
		"peer", sess.PeerAddr.String(),
		"peer_id", string(sess.PeerID),
	)

	// Build EAP-Identity request.
	eapIdentityReq := BuildEAPIdentityRequest(sess.EAPIdentifier)

	// Build response payloads (inside SK).
	respIDPayload := &IDPayload{
		IsInitiator: false,
		IDType:      sess.LocalIDType,
		Data:        sess.LocalID,
	}

	var innerPayloads []Payload
	innerPayloads = append(innerPayloads, respIDPayload)

	// EAP payload wraps the EAP-Identity request.
	innerPayloads = append(innerPayloads, &EAPPayload{
		Data: eapIdentityReq,
	})

	resp, err := h.buildEncryptedResponse(sess, ExchangeIKEAuth, 1, innerPayloads)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP start: building response: %w", err)
	}

	return resp, nil
}

// HandleAuthEAP processes subsequent IKE_AUTH exchanges during an EAP flow.
// This handles EAP-Identity responses, MSCHAPv2 challenge/response, and
// the final AUTH exchange after EAP-Success.
// RFC 7296 §2.16.
func (h *IKEv2Handler) HandleAuthEAP(sess *IKEv2Session, msg *Message, assignIP func() (net.IP, net.IPMask, error), dnsServers []net.IP) (*Message, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	// Decrypt SK payload.
	skPayload := findPayloadAs[*SKPayload](msg.Payloads)
	if skPayload == nil {
		return nil, fmt.Errorf("IKE_AUTH EAP: missing SK payload")
	}

	msgBytes, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP: marshal for AAD: %w", err)
	}
	aad := msgBytes[:HeaderLen]

	decKey := sess.Keys.SK_ei
	intKey := sess.Keys.SK_ai

	innerChain, err := DecryptSKPayload(sess.Encryptor, sess.Integrity, decKey, intKey, aad, skPayload.EncryptedData, msg.Header.NextPayload)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP: decrypt SK: %w", err)
	}

	// After EAP-Success, client sends final IKE_AUTH with AUTH payload.
	if sess.State == StateV2EAPDone {
		return h.handleFinalEAPAuth(sess, innerChain, msg.Header.MessageID, assignIP, dnsServers)
	}

	// During EAP exchange, expect EAP payload.
	eapPayload := findPayloadAs[*EAPPayload](innerChain)
	if eapPayload == nil {
		return nil, fmt.Errorf("IKE_AUTH EAP: missing EAP payload")
	}

	eapPkt, err := ParseEAPPacket(eapPayload.Data)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP: parse EAP: %w", err)
	}

	return h.processEAPResponse(sess, eapPkt, msg.Header.MessageID)
}

// processEAPResponse handles an EAP response from the peer and returns
// the next EAP request or success/failure.
func (h *IKEv2Handler) processEAPResponse(sess *IKEv2Session, pkt *EAPPacket, msgID uint32) (*Message, error) {
	if pkt.Code != EAPCodeResponse {
		return nil, fmt.Errorf("IKE_AUTH EAP: expected Response, got code %d", pkt.Code)
	}

	switch pkt.Type {
	case EAPTypeIdentity:
		return h.handleEAPIdentity(sess, pkt, msgID)

	case EAPTypeMSCHAPv2:
		return h.handleEAPMSCHAPv2(sess, pkt, msgID)

	case EAPTypeTLS:
		return h.handleEAPTLS(sess, pkt, msgID)

	case EAPTypeNAK:
		// Peer rejected our EAP method. Log and send failure.
		log.Warn("IKEv2 EAP: peer sent NAK (rejecting EAP method)",
			"peer", sess.PeerAddr.String())
		return h.sendEAPFailure(sess, msgID)

	default:
		log.Warn("IKEv2 EAP: unsupported EAP type from peer",
			"peer", sess.PeerAddr.String(), "type", pkt.Type)
		return h.sendEAPFailure(sess, msgID)
	}
}

// handleEAPIdentity processes EAP-Identity response and sends the first
// MSCHAPv2 challenge.
func (h *IKEv2Handler) handleEAPIdentity(sess *IKEv2Session, pkt *EAPPacket, msgID uint32) (*Message, error) {
	identity, err := ParseEAPIdentityResponse(pkt)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP: parsing identity: %w", err)
	}

	log.Info("IKEv2 EAP: identity received",
		"peer", sess.PeerAddr.String(),
		"identity", identity,
	)

	// Check if we have EAP credentials for this user.
	_, found := h.getEAPCredentials(identity)
	if !found {
		log.Warn("IKEv2 EAP: unknown user",
			"peer", sess.PeerAddr.String(),
			"identity", identity,
		)
		return h.sendEAPFailure(sess, msgID)
	}

	// Start EAP-MSCHAPv2 challenge.
	sess.EAPMethod = EAPTypeMSCHAPv2

	challenge, err := GenerateMSCHAPv2Challenge()
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP: generating MSCHAPv2 challenge: %w", err)
	}

	mschapState := &MSCHAPv2State{
		ServerChallenge: challenge,
		ServerName:      "swan-ng",
		Username:        identity,
	}
	sess.EAPState = mschapState

	sess.EAPIdentifier++
	mschapID := sess.EAPIdentifier

	eapChallenge := BuildMSCHAPv2Challenge(sess.EAPIdentifier, mschapID, challenge, "swan-ng")

	return h.sendEAPPayload(sess, eapChallenge, msgID)
}

// handleEAPMSCHAPv2 processes EAP-MSCHAPv2 response payloads.
func (h *IKEv2Handler) handleEAPMSCHAPv2(sess *IKEv2Session, pkt *EAPPacket, msgID uint32) (*Message, error) {
	mschapState, ok := sess.EAPState.(*MSCHAPv2State)
	if !ok || mschapState == nil {
		return nil, fmt.Errorf("IKE_AUTH EAP: MSCHAPv2 state not initialized")
	}

	if len(pkt.Data) < 1 {
		return h.sendEAPFailure(sess, msgID)
	}

	opcode := pkt.Data[0]

	switch opcode {
	case MSCHAPv2OpResponse:
		return h.handleMSCHAPv2Response(sess, mschapState, pkt, msgID)

	case MSCHAPv2OpSuccess:
		// Client acknowledges our Success message. Send EAP-Success.
		return h.handleMSCHAPv2SuccessAck(sess, mschapState, msgID)

	default:
		log.Warn("IKEv2 EAP MSCHAPv2: unexpected opcode",
			"peer", sess.PeerAddr.String(), "opcode", opcode)
		return h.sendEAPFailure(sess, msgID)
	}
}

// handleMSCHAPv2Response verifies the client's MSCHAPv2 challenge response.
func (h *IKEv2Handler) handleMSCHAPv2Response(sess *IKEv2Session, state *MSCHAPv2State, pkt *EAPPacket, msgID uint32) (*Message, error) {
	// Look up the user's password.
	password, found := h.getEAPCredentials(state.Username)
	if !found {
		log.Warn("IKEv2 EAP MSCHAPv2: user not found for response",
			"peer", sess.PeerAddr.String(), "user", state.Username)
		return h.sendEAPFailure(sess, msgID)
	}

	// Verify the response.
	authResp, ok := VerifyMSCHAPv2Response(pkt.Data, state.ServerChallenge, state.Username, password)
	if !ok {
		log.Warn("IKEv2 EAP MSCHAPv2: authentication failed",
			"peer", sess.PeerAddr.String(), "user", state.Username)

		// Send MSCHAPv2 Failure inside EAP.
		sess.EAPIdentifier++
		eapFailMsg := BuildMSCHAPv2Failure(sess.EAPIdentifier, sess.EAPIdentifier,
			"E=691 R=0 V=3")
		return h.sendEAPPayload(sess, eapFailMsg, msgID)
	}

	// Save authenticator response and extract peer/NT response for MSK derivation.
	state.AuthResp = authResp

	// Extract peer challenge and NT response from the MSCHAPv2 response data.
	if len(pkt.Data) >= 5+49 {
		responseValue := pkt.Data[5 : 5+49]
		state.PeerChallenge = cloneBytes(responseValue[0:16])
		state.NTResponse = cloneBytes(responseValue[24:48])
	}

	log.Info("IKEv2 EAP MSCHAPv2: challenge-response verified",
		"peer", sess.PeerAddr.String(), "user", state.Username)

	// Send MSCHAPv2 Success inside EAP.
	sess.EAPIdentifier++
	eapSuccess := BuildMSCHAPv2Success(sess.EAPIdentifier, sess.EAPIdentifier, authResp)

	return h.sendEAPPayload(sess, eapSuccess, msgID)
}

// handleMSCHAPv2SuccessAck handles the client's acknowledgment of MSCHAPv2 success.
// After this, we send EAP-Success and transition to EAPDone.
func (h *IKEv2Handler) handleMSCHAPv2SuccessAck(sess *IKEv2Session, state *MSCHAPv2State, msgID uint32) (*Message, error) {
	// Derive MSK from MSCHAPv2 exchange for final AUTH computation.
	password, found := h.getEAPCredentials(state.Username)
	if !found {
		return h.sendEAPFailure(sess, msgID)
	}

	if state.NTResponse != nil {
		sess.EAPMSK = GetMSCHAPv2MSK(password, state.NTResponse)
	}

	sess.EAPIdentifier++
	sess.State = StateV2EAPDone

	log.Info("IKEv2 EAP: MSCHAPv2 complete, sending EAP-Success",
		"peer", sess.PeerAddr.String(), "user", state.Username)

	eapSuccess := BuildEAPSuccess(sess.EAPIdentifier)

	return h.sendEAPPayload(sess, eapSuccess, msgID)
}

// handleFinalEAPAuth processes the final IKE_AUTH after EAP-Success.
// RFC 7296 §2.16: Client sends AUTH payload computed over the initial
// exchange messages using the EAP-derived MSK.
func (h *IKEv2Handler) handleFinalEAPAuth(sess *IKEv2Session, innerChain PayloadChain, msgID uint32, assignIP func() (net.IP, net.IPMask, error), dnsServers []net.IP) (*Message, error) {
	authPayload := findPayloadAs[*AUTHPayload](innerChain)
	if authPayload == nil {
		return nil, fmt.Errorf("IKE_AUTH EAP final: missing AUTH payload")
	}

	// RFC 7296 §2.16: For EAP methods that derive keys (like MSCHAPv2),
	// the AUTH payload is computed using the MSK as the shared secret
	// instead of PSK.
	if sess.EAPMSK != nil {
		sess.PSK = sess.EAPMSK
	}

	// Create a synthetic ID payload from stored peer ID for verification.
	idPayload := &IDPayload{
		IsInitiator: true,
		IDType:      sess.PeerIDType,
		Data:        sess.PeerID,
	}

	// Verify AUTH using EAP-derived MSK as shared secret.
	if err := h.verifyAuth(sess, authPayload, idPayload); err != nil {
		log.Warn("IKEv2 EAP final AUTH verification failed",
			"peer", sess.PeerAddr.String(), "error", err)
		return h.buildAuthError(sess, NotifyAuthenticationFailed)
	}

	// Restore saved payloads from initial IKE_AUTH request.
	saPayload := sess.pendingAuthSA
	tsIPayload := sess.pendingAuthTSi
	tsRPayload := sess.pendingAuthTSr
	cpPayload := sess.pendingAuthCP

	// Select Child SA proposal.
	if saPayload == nil {
		return h.buildAuthError(sess, NotifyNoProposalChosen)
	}

	childSelected, childProp, err := SelectProposal(h.defaultChildProposals, saPayload)
	if err != nil {
		log.Debug("IKE_AUTH EAP final: no child proposal chosen", "error", err)
		return h.buildAuthError(sess, NotifyNoProposalChosen)
	}

	// Generate Child SA SPIs.
	var inSPI [4]byte
	if _, err := rand.Read(inSPI[:]); err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP final: generating child SPI: %w", err)
	}
	childProp.SPI = inSPI[:]

	// Derive Child SA keys.
	childEncKeyLen, childIntKeyLen := childKeyLengths(childSelected)
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

	// Build responder AUTH using EAP MSK.
	respIDPayload := &IDPayload{
		IsInitiator: false,
		IDType:      sess.LocalIDType,
		Data:        sess.LocalID,
	}

	respAuth, err := ComputeIKEv2AuthPSK(sess.PRF, sess.PSK, sess.InitRespBytes,
		sess.NonceI, sess.Keys.SK_pr, respIDPayload)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP final: computing responder AUTH: %w", err)
	}

	// Build response payloads.
	var innerPayloads []Payload
	innerPayloads = append(innerPayloads, respIDPayload)
	innerPayloads = append(innerPayloads, &AUTHPayload{
		Method: AuthSharedKey,
		Data:   respAuth,
	})

	innerPayloads = append(innerPayloads, &SAPayload{
		Proposals: []Proposal{*childProp},
	})

	if tsIPayload != nil {
		innerPayloads = append(innerPayloads, tsIPayload)
	}
	if tsRPayload != nil {
		innerPayloads = append(innerPayloads, tsRPayload)
	}
	if cpReply != nil {
		innerPayloads = append(innerPayloads, cpReply)
	}

	resp, err := h.buildEncryptedResponse(sess, ExchangeIKEAuth, msgID, innerPayloads)
	if err != nil {
		return nil, fmt.Errorf("IKE_AUTH EAP final: building response: %w", err)
	}

	sess.State = StateV2Established

	// Clear pending payloads.
	sess.pendingAuthSA = nil
	sess.pendingAuthTSi = nil
	sess.pendingAuthTSr = nil
	sess.pendingAuthCP = nil

	log.Info("IKEv2 IKE_AUTH established via EAP",
		"peer", sess.PeerAddr.String(),
		"conn", sess.ConnName,
		"eap_method", sess.EAPMethod,
		"child_spi_in", fmt.Sprintf("0x%08x", inSPI),
	)

	return resp, nil
}

// sendEAPPayload wraps an EAP packet in an encrypted IKE_AUTH response.
func (h *IKEv2Handler) sendEAPPayload(sess *IKEv2Session, eapData []byte, msgID uint32) (*Message, error) {
	innerPayloads := []Payload{
		&EAPPayload{Data: eapData},
	}

	return h.buildEncryptedResponse(sess, ExchangeIKEAuth, msgID, innerPayloads)
}

// sendEAPFailure sends an EAP-Failure and resets session state.
func (h *IKEv2Handler) sendEAPFailure(sess *IKEv2Session, msgID uint32) (*Message, error) {
	sess.EAPIdentifier++
	eapFail := BuildEAPFailure(sess.EAPIdentifier)

	log.Info("IKEv2 EAP: sending failure",
		"peer", sess.PeerAddr.String(),
	)

	return h.sendEAPPayload(sess, eapFail, msgID)
}
