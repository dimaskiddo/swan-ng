package ike

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// CertProvider provides server certificates for EAP-TLS.
type CertProvider interface {
	ServerTLSCertificate() (tls.Certificate, error)
	CACertPool() *x509.CertPool
}

// IKEv2Handler handles IKEv2 exchanges (responder).
type IKEv2Handler struct {
	defaultIKEProposals   *SAPayload
	defaultChildProposals *SAPayload
	getConnPSK            func(peerAddr *net.UDPAddr, peerID []byte) (psk []byte, connName string, err error)
	getEAPCredentials     func(username string) (password string, found bool)
	certProvider          CertProvider
	localID               []byte
	localIDType           IDType
	cookieMode            CookieMode
	cookieSecret          []byte // Secret for cookie generation
}

// NewIKEv2Handler creates a new IKEv2 exchange handler.
func NewIKEv2Handler(getConnPSK func(peerAddr *net.UDPAddr, peerID []byte) ([]byte, string, error), getEAPCredentials func(username string) (string, bool), certProvider CertProvider, localID []byte, localIDType IDType, cookieMode CookieMode) *IKEv2Handler {
	// Generate random cookie secret.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Error("Failed to generate cookie secret", "error", err)
	}

	return &IKEv2Handler{
		defaultIKEProposals:   DefaultIKEProposals(),
		defaultChildProposals: DefaultESPProposals(),
		getConnPSK:            getConnPSK,
		getEAPCredentials:     getEAPCredentials,
		certProvider:          certProvider,
		localID:               localID,
		localIDType:           localIDType,
		cookieMode:            cookieMode,
		cookieSecret:          secret,
	}
}

// HandleSAInit processes an IKE_SA_INIT request (responder).
// Returns the response message and a new session.
// RFC 7296 §1.1, §2.
func (h *IKEv2Handler) HandleSAInit(msg *Message, peerAddr *net.UDPAddr) (*Message, *IKEv2Session, error) {
	// Extract SA payload.
	saPayload := findPayloadAs[*SAPayload](msg.Payloads)
	if saPayload == nil {
		return h.buildSAInitError(msg, NotifyInvalidSyntax, nil)
	}

	// Extract KE payload.
	kePayload := findPayloadAs[*KEPayload](msg.Payloads)
	if kePayload == nil {
		return h.buildSAInitError(msg, NotifyInvalidSyntax, nil)
	}

	// Extract Nonce payload.
	noncePayload := findPayloadAs[*NoncePayload](msg.Payloads)
	if noncePayload == nil {
		return h.buildSAInitError(msg, NotifyInvalidSyntax, nil)
	}

	// Check for COOKIE notify (anti-DoS retry).
	cookieNotify := h.findNotifyPayload(msg.Payloads, NotifyCookie)
	if h.cookieMode == CookieModeBusy && cookieNotify == nil {
		// Must have cookie. Send COOKIE notify back.
		return h.buildCookieResponse(msg, peerAddr, noncePayload.NonceData)
	}

	if cookieNotify != nil {
		// Verify cookie.
		prf, _ := NewPRF(PRFHMAC_SHA256)
		if prf != nil && !VerifySAInitCookie(prf, h.cookieSecret, peerAddr,
			msg.Header.InitiatorSPI, noncePayload.NonceData, cookieNotify.NotifyData) {
			log.Warn("IKEv2 SA_INIT: invalid cookie", "peer", peerAddr.String())
			return h.buildSAInitError(msg, NotifyInvalidSyntax, nil)
		}
	}

	// Select IKE SA proposal.
	selected, selectedProp, err := SelectProposal(h.defaultIKEProposals, saPayload)
	if err != nil {
		log.Debug("IKEv2 SA_INIT: no proposal chosen", "peer", peerAddr.String(), "error", err)
		return h.buildSAInitError(msg, NotifyNoProposalChosen, nil)
	}

	// Validate KE DH group matches selected proposal.
	if kePayload.DHGroup != selected.DHID {
		log.Debug("IKEv2 SA_INIT: KE DH group mismatch",
			"offered", kePayload.DHGroup, "selected", selected.DHID)

		// Send INVALID_KE_PAYLOAD with correct group.
		groupBuf := make([]byte, 2)
		groupBuf[0] = byte(selected.DHID >> 8)
		groupBuf[1] = byte(selected.DHID)

		return h.buildSAInitError(msg, NotifyInvalidKEPayload, groupBuf)
	}

	// Generate responder SPI.
	respSPI, err := GenerateIKESPI()
	if err != nil {
		return nil, nil, fmt.Errorf("generating responder SPI: %w", err)
	}

	// Generate DH keypair.
	dh, err := NewDHGroup(selected.DHID)
	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: DH group %d: %w", selected.DHID, err)
	}

	dhPriv, dhPub, err := dh.GenerateKeypair()
	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: DH keygen: %w", err)
	}

	// Compute shared secret.
	sharedSecret, err := dh.ComputeSharedSecret(dhPriv, kePayload.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: DH shared secret: %w", err)
	}

	// Generate responder nonce.
	nonceR, err := GenerateNonce(32)
	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: nonce gen: %w", err)
	}

	// Initialize PRF.
	prf, err := NewPRF(selected.PRFID)
	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: PRF %d: %w", selected.PRFID, err)
	}

	// Determine key sizes.
	encryptor, err := NewIKEEncryptor(selected.EncrID, selected.EncrKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: encryptor: %w", err)
	}

	encKeyLen := encryptor.KeySize()
	if encryptor.IsAEAD() {
		encKeyLen += 4 // AEAD salt
	}

	intKeyLen := 0
	var integrity IntegrityAlgorithm
	if !encryptor.IsAEAD() && selected.IntegID != AuthNone {
		integrity, err = NewIntegrity(selected.IntegID)
		if err != nil {
			return nil, nil, fmt.Errorf("SA_INIT: integrity %d: %w", selected.IntegID, err)
		}

		intKeyLen = integrity.KeySize()
	}

	prfKeyLen := prf.KeySize()

	// Derive keys.
	keys, err := DeriveIKEv2Keys(prf, sharedSecret,
		noncePayload.NonceData, nonceR,
		msg.Header.InitiatorSPI, respSPI,
		encKeyLen, intKeyLen, prfKeyLen)

	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: key derivation: %w", err)
	}

	// Create session.
	sess := &IKEv2Session{
		InitiatorSPI: msg.Header.InitiatorSPI,
		ResponderSPI: respSPI,
		IsInitiator:  false,
		PeerAddr:     peerAddr,
		State:        StateV2InitRecv,
		EncAlg:       selected.EncrID,
		PrfAlg:       selected.PRFID,
		IntegAlg:     selected.IntegID,
		DHGroupID:    selected.DHID,
		KeyLength:    selected.EncrKeyLen,
		NonceI:       cloneBytes(noncePayload.NonceData),
		NonceR:       nonceR,
		DHPrivKey:    dhPriv,
		DHPubKey:     dhPub,
		PeerDHPubKey: cloneBytes(kePayload.Data),
		SharedSecret: sharedSecret,
		Keys:         keys,
		PRF:          prf,
		Encryptor:    encryptor,
		Integrity:    integrity,
		LocalID:      h.localID,
		LocalIDType:  h.localIDType,
		CreatedAt:    time.Now(),
	}

	// Save raw request bytes for AUTH computation.
	reqBytes, err := msg.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: marshal init request: %w", err)
	}
	sess.InitReqBytes = reqBytes

	// Check for NAT detection payloads.
	h.processNATDetection(sess, msg)

	// Check for fragmentation support.
	if h.findNotifyPayload(msg.Payloads, NotifyIKEv2FragmentationSupported) != nil {
		sess.PeerSupportsFragmentation = true
	}

	// Build response message.
	respSA := &SAPayload{Proposals: []Proposal{*selectedProp}}
	respKE := &KEPayload{DHGroup: selected.DHID, Data: dhPub}
	respNonce := &NoncePayload{NonceData: nonceR}

	respPayloads := PayloadChain{
		{Payload: respSA},
		{Payload: respKE},
		{Payload: respNonce},
	}

	// Add NAT detection notifies.
	natSrc := ComputeNATDetection(sess.InitiatorSPI, sess.ResponderSPI, peerAddr.IP, uint16(peerAddr.Port))
	respPayloads = append(respPayloads, ParsedPayload{Payload: &NotifyPayload{
		NotifyMsgType: NotifyNATDetectionSourceIP,
		NotifyData:    natSrc,
	}})

	// For destination, use our own address (we don't know it here, use peer's for now).
	natDst := ComputeNATDetection(sess.InitiatorSPI, sess.ResponderSPI, peerAddr.IP, uint16(peerAddr.Port))
	respPayloads = append(respPayloads, ParsedPayload{Payload: &NotifyPayload{
		NotifyMsgType: NotifyNATDetectionDestIP,
		NotifyData:    natDst,
	}})

	// Announce fragmentation support.
	respPayloads = append(respPayloads, ParsedPayload{Payload: &NotifyPayload{
		NotifyMsgType: NotifyIKEv2FragmentationSupported,
	}})

	resp := &Message{
		Header: Header{
			InitiatorSPI: sess.InitiatorSPI,
			ResponderSPI: sess.ResponderSPI,
			ExchangeType: ExchangeIKESAInit,
		},
		Payloads: respPayloads,
	}
	resp.Header.SetIKEv2()
	resp.Header.SetResponseFlags(false) // We are responder

	// Save raw response bytes for AUTH computation.
	respBytes, err := resp.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("SA_INIT: marshal init response: %w", err)
	}
	sess.InitRespBytes = respBytes

	log.Info("IKEv2 SA_INIT processed",
		"peer", peerAddr.String(),
		"encr", selected.EncrID,
		"prf", selected.PRFID,
		"dh", selected.DHID,
	)

	return resp, sess, nil
}

// processNATDetection checks NAT detection payloads in SA_INIT.
func (h *IKEv2Handler) processNATDetection(sess *IKEv2Session, msg *Message) {
	for _, p := range msg.Payloads {
		notify, ok := p.Payload.(*NotifyPayload)
		if !ok {
			continue
		}

		switch notify.NotifyMsgType {
		case NotifyNATDetectionSourceIP:
			if !CheckNATDetection(notify.NotifyData,
				sess.InitiatorSPI, sess.ResponderSPI,
				sess.PeerAddr.IP, uint16(sess.PeerAddr.Port)) {
				sess.BehindNATRemote = true
				log.Debug("IKEv2: peer is behind NAT", "peer", sess.PeerAddr.String())
			}

		case NotifyNATDetectionDestIP:
			// We can't fully verify our own address here without knowing our
			// local address. Mark as potentially behind NAT if hash doesn't match
			// any of our addresses. For now, assume not behind NAT.
		}
	}
}

// findNotifyPayload finds the first Notify payload with the given type.
func (h *IKEv2Handler) findNotifyPayload(chain PayloadChain, notifyType NotifyType) *NotifyPayload {
	for _, p := range chain {
		notify, ok := p.Payload.(*NotifyPayload)
		if ok && notify.NotifyMsgType == notifyType {
			return notify
		}
	}

	return nil
}

// buildSAInitError builds an error response for SA_INIT.
func (h *IKEv2Handler) buildSAInitError(req *Message, notifyType NotifyType, data []byte) (*Message, *IKEv2Session, error) {
	resp := &Message{
		Header: Header{
			InitiatorSPI: req.Header.InitiatorSPI,
			ExchangeType: ExchangeIKESAInit,
		},
		Payloads: PayloadChain{
			{Payload: &NotifyPayload{
				NotifyMsgType: notifyType,
				NotifyData:    data,
			}},
		},
	}
	resp.Header.SetIKEv2()
	resp.Header.SetResponseFlags(false)

	return resp, nil, nil
}

// buildCookieResponse builds a COOKIE notify response for SA_INIT anti-DoS.
func (h *IKEv2Handler) buildCookieResponse(req *Message, peerAddr *net.UDPAddr, ni []byte) (*Message, *IKEv2Session, error) {
	prf, _ := NewPRF(PRFHMAC_SHA256)
	cookie := GenerateSAInitCookie(prf, h.cookieSecret, peerAddr, req.Header.InitiatorSPI, ni)

	resp := &Message{
		Header: Header{
			InitiatorSPI: req.Header.InitiatorSPI,
			ExchangeType: ExchangeIKESAInit,
		},
		Payloads: PayloadChain{
			{Payload: &NotifyPayload{
				NotifyMsgType: NotifyCookie,
				NotifyData:    cookie,
			}},
		},
	}
	resp.Header.SetIKEv2()
	resp.Header.SetResponseFlags(false)

	log.Debug("IKEv2 SA_INIT: cookie required", "peer", peerAddr.String())
	return resp, nil, nil
}
