package ike

import (
	"encoding/binary"
	"fmt"
)

// HeaderLen is the fixed size of the IKE/ISAKMP header per
// RFC 7296 §3.1 (IKEv2) and RFC 2408 §3.1 (ISAKMP/IKEv1).
// Both versions share the same 28-byte header layout.
const HeaderLen = 28

// IKE version constants.
const (
	IKEv1Major uint8 = 1
	IKEv1Minor uint8 = 0
	IKEv2Major uint8 = 2
	IKEv2Minor uint8 = 0
)

// ExchangeType identifies the type of IKE exchange.
type ExchangeType uint8

const (
	// IKEv1 exchange types (RFC 2408 §3.1).
	ExchangeBase            ExchangeType = 0
	ExchangeIdentityProtect ExchangeType = 2  // Main Mode
	ExchangeAuthOnly        ExchangeType = 3  // Authentication Only
	ExchangeAggressive      ExchangeType = 4  // Aggressive Mode
	ExchangeInformationalV1 ExchangeType = 5  // Informational (IKEv1)
	ExchangeQuickMode       ExchangeType = 32 // Quick Mode (Phase 2)
	ExchangeNewGroupMode    ExchangeType = 33 // New Group Mode

	// IKEv2 exchange types (RFC 7296 §3.1).
	ExchangeIKESAInit     ExchangeType = 34 // IKE_SA_INIT
	ExchangeIKEAuth       ExchangeType = 35 // IKE_AUTH
	ExchangeCreateChildSA ExchangeType = 36 // CREATE_CHILD_SA
	ExchangeInformational ExchangeType = 37 // INFORMATIONAL (IKEv2)
)

// String returns a human-readable exchange type name.
func (et ExchangeType) String() string {
	switch et {
	case ExchangeBase:
		return "Base"

	case ExchangeIdentityProtect:
		return "Main Mode"

	case ExchangeAuthOnly:
		return "Auth Only"

	case ExchangeAggressive:
		return "Aggressive Mode"

	case ExchangeInformationalV1:
		return "Informational (v1)"

	case ExchangeQuickMode:
		return "Quick Mode"

	case ExchangeNewGroupMode:
		return "New Group Mode"

	case ExchangeIKESAInit:
		return "IKE_SA_INIT"

	case ExchangeIKEAuth:
		return "IKE_AUTH"

	case ExchangeCreateChildSA:
		return "CREATE_CHILD_SA"

	case ExchangeInformational:
		return "INFORMATIONAL"

	default:
		return fmt.Sprintf("Unknown(%d)", et)
	}
}

// IKEv2 header flags (RFC 7296 §3.1).
const (
	// FlagInitiator is set if the message sender is the original IKE SA initiator.
	FlagInitiator uint8 = 0x08

	// FlagVersion is set if the sender can handle a higher major version.
	FlagVersion uint8 = 0x10

	// FlagResponse is set if this message is a response to a request.
	FlagResponse uint8 = 0x20
)

// IKEv1 header flags (RFC 2408 §3.1).
const (
	// FlagV1Encryption indicates payloads following the header are encrypted.
	FlagV1Encryption uint8 = 0x01

	// FlagV1Commit requests the responder to delay SA usage until confirmed.
	FlagV1Commit uint8 = 0x02

	// FlagV1AuthOnly indicates authentication-only (no encryption).
	FlagV1AuthOnly uint8 = 0x04
)

// Header represents the 28-byte IKE/ISAKMP header shared by IKEv1 and IKEv2.
//
// Wire format (RFC 7296 §3.1):
//
//	                     1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         Initiator SPI                        |
//	|                           (8 octets)                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                         Responder SPI                        |
//	|                           (8 octets)                         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Next Payload  |MjVer |MnVer |  Exchange Type |     Flags     |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                          Message ID                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                            Length                            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Header struct {
	InitiatorSPI [8]byte      // Initiator's Security Parameter Index
	ResponderSPI [8]byte      // Responder's Security Parameter Index
	NextPayload  PayloadType  // Type of the first payload following this header
	MajorVersion uint8        // Major version (1 for IKEv1, 2 for IKEv2)
	MinorVersion uint8        // Minor version (0 for both)
	ExchangeType ExchangeType // Exchange type identifier
	Flags        uint8        // Flags field
	MessageID    uint32       // Message identifier for request/response matching
	Length       uint32       // Total message length including header
}

// ParseHeader parses a 28-byte IKE header from buf.
// Returns error if buf is too short. Does not validate header contents —
// call Validate() separately for semantic checks.
func ParseHeader(buf []byte) (Header, error) {
	if len(buf) < HeaderLen {
		return Header{}, fmt.Errorf("buffer too short for IKE header: need %d, got %d",
			HeaderLen, len(buf))
	}

	var h Header

	copy(h.InitiatorSPI[:], buf[0:8])
	copy(h.ResponderSPI[:], buf[8:16])

	h.NextPayload = PayloadType(buf[16])
	h.MajorVersion = buf[17] >> 4
	h.MinorVersion = buf[17] & 0x0F
	h.ExchangeType = ExchangeType(buf[18])
	h.Flags = buf[19]
	h.MessageID = binary.BigEndian.Uint32(buf[20:24])
	h.Length = binary.BigEndian.Uint32(buf[24:28])

	return h, nil
}

// Marshal serializes the header into buf. buf must be at least HeaderLen bytes.
// Uses zero-allocation strategy per AGENTS.md §10.
func (h Header) Marshal(buf []byte) error {
	if len(buf) < HeaderLen {
		return fmt.Errorf("buffer too short for IKE header marshal: need %d, got %d",
			HeaderLen, len(buf))
	}

	copy(buf[0:8], h.InitiatorSPI[:])
	copy(buf[8:16], h.ResponderSPI[:])

	buf[16] = byte(h.NextPayload)
	buf[17] = (h.MajorVersion << 4) | (h.MinorVersion & 0x0F)
	buf[18] = byte(h.ExchangeType)
	buf[19] = h.Flags

	binary.BigEndian.PutUint32(buf[20:24], h.MessageID)
	binary.BigEndian.PutUint32(buf[24:28], h.Length)

	return nil
}

// MarshalBinary allocates a new buffer and returns the serialized header.
func (h Header) MarshalBinary() []byte {
	buf := make([]byte, HeaderLen)
	// Marshal into correctly-sized buffer never fails.
	_ = h.Marshal(buf)
	return buf
}

// IsIKEv2 returns true if the header indicates IKEv2 (major version 2).
func (h Header) IsIKEv2() bool {
	return h.MajorVersion == IKEv2Major
}

// IsIKEv1 returns true if the header indicates IKEv1 (major version 1).
func (h Header) IsIKEv1() bool {
	return h.MajorVersion == IKEv1Major
}

// IsResponse returns true if the Response flag is set (IKEv2 only).
func (h Header) IsResponse() bool {
	return h.Flags&FlagResponse != 0
}

// IsInitiator returns true if the Initiator flag is set (IKEv2 only).
// Note: this indicates the sender is the original IKE SA initiator,
// not necessarily the sender of this specific message.
func (h Header) IsInitiator() bool {
	return h.Flags&FlagInitiator != 0
}

// IsEncrypted returns true if the Encryption flag is set (IKEv1 only).
// When set, all payloads after the header are encrypted with SKEYID_e.
func (h Header) IsEncrypted() bool {
	return h.Flags&FlagV1Encryption != 0
}

// SPIPair returns the combined 16-byte SPI pair (InitiatorSPI || ResponderSPI)
// for use as a session lookup key in the SA database.
func (h Header) SPIPair() [16]byte {
	var pair [16]byte

	copy(pair[:8], h.InitiatorSPI[:])
	copy(pair[8:], h.ResponderSPI[:])

	return pair
}

// Validate performs basic sanity checks on the parsed header.
// Per AGENTS.md §12, callers should log and drop on error, never panic.
func (h Header) Validate() error {
	if h.MajorVersion == 0 {
		return fmt.Errorf("invalid IKE major version 0")
	}

	if h.MajorVersion > 2 {
		return fmt.Errorf("unsupported IKE major version %d", h.MajorVersion)
	}

	if h.Length < HeaderLen {
		return fmt.Errorf("IKE message length %d is less than header size %d",
			h.Length, HeaderLen)
	}

	// IKEv2: initiator SPI must be non-zero (RFC 7296 §3.1).
	if h.MajorVersion == IKEv2Major {
		var zeroSPI [8]byte
		if h.InitiatorSPI == zeroSPI {
			return fmt.Errorf("IKEv2 initiator SPI must not be zero")
		}
	}

	return nil
}

// SetIKEv1 sets the version fields for an IKEv1 header.
func (h *Header) SetIKEv1() {
	h.MajorVersion = IKEv1Major
	h.MinorVersion = IKEv1Minor
}

// SetIKEv2 sets the version fields for an IKEv2 header.
func (h *Header) SetIKEv2() {
	h.MajorVersion = IKEv2Major
	h.MinorVersion = IKEv2Minor
}

// SetResponseFlags sets the IKEv2 response flags.
// initiator: true if sender is the original IKE SA initiator.
func (h *Header) SetResponseFlags(initiator bool) {
	h.Flags = FlagResponse
	if initiator {
		h.Flags |= FlagInitiator
	}
}

// SetRequestFlags sets the IKEv2 request flags.
// initiator: true if sender is the original IKE SA initiator.
func (h *Header) SetRequestFlags(initiator bool) {
	h.Flags = 0
	if initiator {
		h.Flags |= FlagInitiator
	}
}
