package ike

import (
	"net"
	"sync"
)

// IKEv1State tracks the Phase 1 negotiation state.
type IKEv1State uint8

const (
	StateV1Idle        IKEv1State = iota
	StateV1MainSARecv             // Received msg1 (SA), sent msg2
	StateV1MainKERecv             // Received msg3 (KE+Nonce), sent msg4
	StateV1MainIDRecv             // Received msg5 (ID+Hash), sent msg6 — done
	StateV1AggrRecv               // Aggressive: received msg1, sent msg2
	StateV1AggrDone               // Aggressive: received msg3 — done
	StateV1Established            // Phase 1 SA established
	StateV1XAUTHSent              // XAUTH challenge sent, awaiting reply
	StateV1XAUTHDone              // XAUTH completed successfully
	StateV1Deleting               // Phase 1 SA is deleting
)

func (s IKEv1State) String() string {
	names := [...]string{"Idle", "MainSARecv", "MainKERecv", "MainIDRecv", "AggrRecv", "AggrDone", "Established", "XAUTHSent", "XAUTHDone", "Deleting"}
	if int(s) < len(names) {
		return names[s]
	}

	return "Unknown"
}

// IKEv1Session holds state for a single IKEv1 Phase 1 SA.
type IKEv1Session struct {
	mu sync.Mutex

	// SPIs (cookies in IKEv1 terminology).
	CookieI [8]byte
	CookieR [8]byte

	State IKEv1State

	// Negotiated algorithms.
	EncAlg     uint16
	HashAlg    uint16
	AuthMethod uint16
	DHGroupID  uint16
	KeyLength  uint16

	// Crypto state.
	DHPrivKey    []byte
	DHPubKey     []byte
	PeerDHPubKey []byte
	SharedSecret []byte

	NonceI []byte
	NonceR []byte

	// Derived keys.
	Keys *IKEv1KeyMaterial

	// Encryption/integrity instances.
	PRF       PRFAlgorithm
	Encryptor IKEEncryptor

	// IV state: IKEv1 uses CBC IV chaining.
	// First IV = hash(Ni || Nr)[0:blockSize].
	// Subsequent IVs = last ciphertext block of prev message.
	CurrentIV []byte

	// Peer info.
	PeerAddr *net.UDPAddr
	PeerID   []byte
	LocalID  []byte

	// PSK for this session (from connection config).
	PSK []byte

	// Connection config name.
	ConnName string

	// XAUTH state.
	XAUTHEnabled bool   // true if connection uses XAUTH+PSK
	XAUTHUser    string // Authenticated XAUTH username

	// Message ID counter for Quick Mode.
	NextMsgID uint32

	// Child SAs created via Quick Mode.
	ChildSAs []*IKEv1ChildSA
}

// IKEv1ChildSA holds state for a Quick Mode (Phase 2) SA.
type IKEv1ChildSA struct {
	MsgID        uint32
	InSPI        [4]byte // Our inbound ESP SPI
	OutSPI       [4]byte // Peer's inbound ESP SPI (our outbound)
	EncrKey      []byte
	IntegKey     []byte
	PeerEncrKey  []byte
	PeerIntegKey []byte
	EncrID       uint16
	IntegID      uint16
	KeyLength    uint16
}

// SPIPair returns the 16-byte combined cookie pair for session lookup.
func (s *IKEv1Session) SPIPair() [16]byte {
	var pair [16]byte

	copy(pair[:8], s.CookieI[:])
	copy(pair[8:], s.CookieR[:])

	return pair
}
