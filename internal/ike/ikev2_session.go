package ike

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"net"
	"sync"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// ---- IKEv2 Session State ----

// IKEv2State tracks the IKEv2 SA negotiation state.
type IKEv2State uint8

const (
	StateV2Idle          IKEv2State = iota
	StateV2InitRecv                 // Responder: received SA_INIT, sent response
	StateV2EAPInProgress            // EAP exchange in progress (multi-round IKE_AUTH)
	StateV2EAPDone                  // EAP completed, awaiting final AUTH exchange
	StateV2Established              // IKE SA established
	StateV2Rekeying                 // Rekeying in progress
	StateV2Deleting                 // Deletion in progress
)

func (s IKEv2State) String() string {
	names := [...]string{"Idle", "InitRecv", "EAPInProgress", "EAPDone", "Established", "Rekeying", "Deleting"}
	if int(s) < len(names) {
		return names[s]
	}

	return "Unknown"
}

// ---- Cookie Anti-DoS Mode ----

// CookieMode controls SA_INIT cookie anti-DoS behavior.
type CookieMode uint8

const (
	CookieModeAuto      CookieMode = iota // Auto: enable cookies under load
	CookieModeBusy                        // Always require cookies
	CookieModeUnlimited                   // Never require cookies
)

// ParseCookieMode parses a cookie mode string from config.
func ParseCookieMode(s string) CookieMode {
	switch s {
	case "busy":
		return CookieModeBusy

	case "unlimited":
		return CookieModeUnlimited

	default:
		return CookieModeAuto
	}
}

// ---- IKEv2 Session ----

// IKEv2Session holds state for a single IKEv2 SA.
type IKEv2Session struct {
	mu sync.Mutex

	// SPIs.
	InitiatorSPI [8]byte
	ResponderSPI [8]byte
	IsInitiator  bool
	PeerAddr     *net.UDPAddr
	State        IKEv2State

	// Negotiated algorithms.
	EncAlg    uint16
	PrfAlg    uint16
	IntegAlg  uint16
	DHGroupID uint16
	KeyLength uint16

	// Nonces.
	NonceI []byte
	NonceR []byte

	// DH state.
	DHPrivKey    []byte
	DHPubKey     []byte
	PeerDHPubKey []byte
	SharedSecret []byte

	// Derived keys.
	Keys *IKEv2KeyMaterial
	PRF  PRFAlgorithm

	// Encryption/Integrity instances (created after key derivation).
	Encryptor IKEEncryptor
	Integrity IntegrityAlgorithm // nil for AEAD

	// Raw init messages for AUTH computation (RFC 7296 §2.15).
	InitReqBytes  []byte
	InitRespBytes []byte

	// Identities.
	PeerIDType  IDType
	PeerID      []byte
	LocalID     []byte
	LocalIDType IDType

	// Config.
	ConnName string
	PSK      []byte

	// NAT detection (RFC 7296 §2.23).
	BehindNATLocal  bool
	BehindNATRemote bool

	// Fragmentation support (RFC 7383).
	PeerSupportsFragmentation bool

	// Message ID counters (RFC 7296 §2.2).
	NextMsgID uint32

	// Child SAs.
	ChildSAs []*IKEv2ChildSA

	// EAP state (for EAP-MSCHAPv2 / EAP-TLS multi-round auth).
	// Holds *MSCHAPv2State, *EAPTLSState, or nil for non-EAP auth.
	EAPState      interface{}
	EAPIdentifier uint8  // Current EAP packet identifier counter
	EAPMethod     uint8  // Negotiated EAP method (EAPTypeMSCHAPv2, EAPTypeTLS)
	EAPMSK        []byte // Master Session Key derived from EAP method

	// Pending payloads from initial IKE_AUTH request (saved during EAP exchange).
	// After EAP completes, these are used to finalize Child SA establishment.
	pendingAuthSA  *SAPayload
	pendingAuthTSi *TSPayload
	pendingAuthTSr *TSPayload
	pendingAuthCP  *CPPayload

	CreatedAt time.Time
}

// IKEv2ChildSA holds state for an IKEv2 Child SA.
type IKEv2ChildSA struct {
	InSPI        [4]byte // Our inbound ESP SPI
	OutSPI       [4]byte // Peer's inbound ESP SPI (our outbound)
	EncrKey      []byte  // Our encrypt key (outbound)
	IntegKey     []byte  // Our integrity key (outbound)
	PeerEncrKey  []byte  // Peer encrypt key (inbound)
	PeerIntegKey []byte  // Peer integrity key (inbound)
	EncrID       uint16
	IntegID      uint16
	KeyLength    uint16
}

// SPIPair returns the 16-byte combined SPI pair for session lookup.
func (s *IKEv2Session) SPIPair() [16]byte {
	var pair [16]byte

	copy(pair[:8], s.InitiatorSPI[:])
	copy(pair[8:], s.ResponderSPI[:])

	return pair
}

// ---- SK Payload Encryption/Decryption (RFC 7296 §3.14) ----

// EncryptSKPayload encrypts a payload chain into an SK payload.
// Returns the complete SK payload body: IV || Encrypted(payloads + padding) || ICV.
//
// For non-AEAD (AES-CBC + HMAC):
//
//	SK = IV || CBC(pad(payloads)) || HMAC(header || IV || ciphertext)
//
// For AEAD (AES-GCM):
//
//	SK = IV || AEAD_Encrypt(payloads, AAD=header)
func EncryptSKPayload(enc IKEEncryptor, integ IntegrityAlgorithm, encKey, integKey []byte, ikeMsgHeader []byte, payloads []Payload) (firstPayloadType PayloadType, skBody []byte, err error) {
	// Marshal the inner payload chain.
	plaintext, firstPT, err := MarshalPayloadChain(payloads)
	if err != nil {
		return 0, nil, fmt.Errorf("marshaling SK inner payloads: %w", err)
	}

	// Generate random IV.
	iv := make([]byte, enc.IVSize())
	if _, err := rand.Read(iv); err != nil {
		return 0, nil, fmt.Errorf("generating SK IV: %w", err)
	}

	if enc.IsAEAD() {
		// AEAD mode: IV || AEAD_Encrypt(plaintext, AAD=header)
		// Add 1 byte pad length at end of plaintext.
		padLen := 0 // AEAD doesn't need block alignment
		padded := make([]byte, len(plaintext)+1+padLen)

		copy(padded, plaintext)
		padded[len(padded)-1] = byte(padLen)

		ciphertext, err := enc.Encrypt(encKey, iv, padded, ikeMsgHeader)
		if err != nil {
			return 0, nil, fmt.Errorf("AEAD encrypt SK: %w", err)
		}

		// SK body = IV || ciphertext (includes ICV tag)
		skBody = make([]byte, len(iv)+len(ciphertext))
		copy(skBody, iv)
		copy(skBody[len(iv):], ciphertext)
	} else {
		// Non-AEAD: IV || CBC(pad(plaintext + padlen)) || HMAC
		// Add PKCS#7-style padding with pad length byte at end.
		blockSize := enc.BlockSize()

		// plaintext + 1 (pad length byte) must be block-aligned.
		totalLen := len(plaintext) + 1
		padLen := 0
		if totalLen%blockSize != 0 {
			padLen = blockSize - (totalLen % blockSize)
		}

		padded := make([]byte, len(plaintext)+padLen+1)
		copy(padded, plaintext)

		// Fill padding bytes (can be random, but zeros are fine per RFC 7296).
		padded[len(padded)-1] = byte(padLen)

		ciphertext, err := enc.Encrypt(encKey, iv, padded, nil)
		if err != nil {
			return 0, nil, fmt.Errorf("CBC encrypt SK: %w", err)
		}

		// Compute integrity: HMAC over (header || IV || ciphertext)
		if integ == nil {
			return 0, nil, fmt.Errorf("non-AEAD cipher requires integrity algorithm")
		}

		// Build data for HMAC: header || genericPayloadHeader || IV || ciphertext
		// The ICV is computed over the entire IKE message up to but not including the ICV itself.
		// For SK payload, this means: IKE header + SK payload header + IV + ciphertext.
		// The caller must adjust the header length field before computing.
		macInput := make([]byte, len(ikeMsgHeader)+len(iv)+len(ciphertext))
		copy(macInput, ikeMsgHeader)
		copy(macInput[len(ikeMsgHeader):], iv)
		copy(macInput[len(ikeMsgHeader)+len(iv):], ciphertext)

		icv := integ.Compute(integKey, macInput)

		// SK body = IV || ciphertext || ICV
		skBody = make([]byte, len(iv)+len(ciphertext)+len(icv))
		copy(skBody, iv)
		copy(skBody[len(iv):], ciphertext)
		copy(skBody[len(iv)+len(ciphertext):], icv)
	}

	return firstPT, skBody, nil
}

// DecryptSKPayload decrypts an SK payload and returns the inner payload chain.
//
// skBody = IV || ciphertext || ICV (non-AEAD) or IV || AEAD_ciphertext (AEAD)
func DecryptSKPayload(enc IKEEncryptor, integ IntegrityAlgorithm, encKey, integKey []byte, ikeMsgHeader []byte, skBody []byte, firstInnerPayload PayloadType) (PayloadChain, error) {
	ivSize := enc.IVSize()

	if len(skBody) < ivSize+1 {
		return nil, fmt.Errorf("SK payload too short: %d bytes", len(skBody))
	}

	iv := skBody[:ivSize]

	if enc.IsAEAD() {
		// AEAD: IV || AEAD_ciphertext (last 16 bytes is GCM tag)
		ciphertext := skBody[ivSize:]

		plaintext, err := enc.Decrypt(encKey, iv, ciphertext, ikeMsgHeader)
		if err != nil {
			return nil, fmt.Errorf("AEAD decrypt SK: %w", err)
		}

		// Strip padding: last byte is pad length.
		if len(plaintext) < 1 {
			return nil, fmt.Errorf("decrypted SK payload empty")
		}

		padLen := int(plaintext[len(plaintext)-1])
		payloadEnd := len(plaintext) - 1 - padLen
		if payloadEnd < 0 {
			return nil, fmt.Errorf("invalid SK padding: padLen=%d, total=%d", padLen, len(plaintext))
		}

		return ParsePayloadChain(plaintext[:payloadEnd], firstInnerPayload, true)
	}

	// Non-AEAD: IV || ciphertext || ICV
	if integ == nil {
		return nil, fmt.Errorf("non-AEAD cipher requires integrity algorithm")
	}

	icvLen := integ.OutputSize()
	if len(skBody) < ivSize+icvLen+1 {
		return nil, fmt.Errorf("SK payload too short for ICV: %d bytes", len(skBody))
	}

	ciphertext := skBody[ivSize : len(skBody)-icvLen]
	receivedICV := skBody[len(skBody)-icvLen:]

	// Verify integrity: HMAC over (header || IV || ciphertext)
	macInput := make([]byte, len(ikeMsgHeader)+ivSize+len(ciphertext))
	copy(macInput, ikeMsgHeader)
	copy(macInput[len(ikeMsgHeader):], iv)
	copy(macInput[len(ikeMsgHeader)+ivSize:], ciphertext)

	if !integ.Verify(integKey, macInput, receivedICV) {
		log.Warn("IKEv2 SK payload integrity check failed")
		return nil, fmt.Errorf("SK integrity check failed")
	}

	plaintext, err := enc.Decrypt(encKey, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("CBC decrypt SK: %w", err)
	}

	// Strip padding.
	if len(plaintext) < 1 {
		return nil, fmt.Errorf("decrypted SK payload empty")
	}

	padLen := int(plaintext[len(plaintext)-1])
	payloadEnd := len(plaintext) - 1 - padLen
	if payloadEnd < 0 {
		return nil, fmt.Errorf("invalid SK padding: padLen=%d, total=%d", padLen, len(plaintext))
	}

	return ParsePayloadChain(plaintext[:payloadEnd], firstInnerPayload, true)
}

// ---- NAT Detection (RFC 7296 §2.23) ----

// ComputeNATDetection computes the NAT_DETECTION_*_IP hash.
// hash = SHA-1(SPIi || SPIr || IP || Port)
func ComputeNATDetection(spiI, spiR [8]byte, addr net.IP, port uint16) []byte {
	h := sha1.New()
	h.Write(spiI[:])
	h.Write(spiR[:])
	h.Write(addr.To4())

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, port)

	h.Write(portBuf)

	return h.Sum(nil)
}

// CheckNATDetection checks if the NAT detection hash matches.
func CheckNATDetection(expected []byte, spiI, spiR [8]byte, addr net.IP, port uint16) bool {
	computed := ComputeNATDetection(spiI, spiR, addr, port)
	return hashEqual(computed, expected)
}

// ---- IKEv2 AUTH Computation (RFC 7296 §2.15) ----

// ComputeIKEv2AuthPSK computes the PSK authentication data.
// AUTH = PRF(PRF(Shared Secret, "Key Pad for IKEv2"), <SignedOctets>)
//
// SignedOctets for initiator:
//
//	InitReqBytes | NonceR | PRF(SK_pi, IDi')
//
// SignedOctets for responder:
//
//	InitRespBytes | NonceI | PRF(SK_pr, IDr')
func ComputeIKEv2AuthPSK(prf PRFAlgorithm, psk []byte, initBytes []byte, peerNonce []byte, skP []byte, idPayload Payload) ([]byte, error) {
	// Marshal ID payload to get IDx'.
	idBytes, err := idPayload.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling ID for auth: %w", err)
	}

	// IDx' = ID payload body (strip generic payload header).
	idBody := idBytes
	if len(idBytes) > PayloadHeaderLen {
		idBody = idBytes[PayloadHeaderLen:]
	}

	// PRF(SK_px, IDx')
	prfID := prf.Compute(skP, idBody)

	// SignedOctets = initBytes | peerNonce | PRF(SK_px, IDx')
	signedOctets := make([]byte, len(initBytes)+len(peerNonce)+len(prfID))
	copy(signedOctets, initBytes)
	copy(signedOctets[len(initBytes):], peerNonce)
	copy(signedOctets[len(initBytes)+len(peerNonce):], prfID)

	// AUTH = PRF(PRF(PSK, "Key Pad for IKEv2"), SignedOctets)
	keyPad := []byte("Key Pad for IKEv2")
	authKey := prf.Compute(psk, keyPad)
	authData := prf.Compute(authKey, signedOctets)

	return authData, nil
}

// ComputeIKEv2AuthCert computes signed octets for certificate-based AUTH.
// Returns the data that must be signed by the private key.
func ComputeIKEv2AuthCert(prf PRFAlgorithm, initBytes []byte, peerNonce []byte, skP []byte, idPayload Payload) ([]byte, error) {
	idBytes, err := idPayload.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling ID for cert auth: %w", err)
	}

	idBody := idBytes
	if len(idBytes) > PayloadHeaderLen {
		idBody = idBytes[PayloadHeaderLen:]
	}

	prfID := prf.Compute(skP, idBody)

	signedOctets := make([]byte, len(initBytes)+len(peerNonce)+len(prfID))
	copy(signedOctets, initBytes)
	copy(signedOctets[len(initBytes):], peerNonce)
	copy(signedOctets[len(initBytes)+len(peerNonce):], prfID)

	return signedOctets, nil
}

// ---- Cookie Generation (RFC 7296 §2.6) ----

// GenerateSAInitCookie generates a cookie for SA_INIT anti-DoS.
// Cookie = PRF(SecretKey, VersionIDofSecret || IPi || SPIi || Ni)
func GenerateSAInitCookie(prf PRFAlgorithm, secretKey []byte, peerAddr *net.UDPAddr, spiI [8]byte, ni []byte) []byte {
	var hashFunc func() hash.Hash

	switch prf.ID() {
	case PRFHMAC_SHA256:
		hashFunc = sha256.New

	default:
		hashFunc = sha1.New
	}

	h := hashFunc()
	h.Write(secretKey)

	if peerAddr != nil && peerAddr.IP != nil {
		h.Write(peerAddr.IP.To4())
	}

	h.Write(spiI[:])
	h.Write(ni)

	return h.Sum(nil)
}

// VerifySAInitCookie verifies a cookie received in SA_INIT retry.
func VerifySAInitCookie(prf PRFAlgorithm, secretKey []byte, peerAddr *net.UDPAddr, spiI [8]byte, ni []byte, cookie []byte) bool {
	expected := GenerateSAInitCookie(prf, secretKey, peerAddr, spiI, ni)
	return hashEqual(expected, cookie)
}
