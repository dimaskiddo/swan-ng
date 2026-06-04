package ike

import (
	"encoding/binary"
	"fmt"
)

// ---- EAP Code Values (RFC 3748 §4) ----

const (
	EAPCodeRequest  uint8 = 1
	EAPCodeResponse uint8 = 2
	EAPCodeSuccess  uint8 = 3
	EAPCodeFailure  uint8 = 4
)

// ---- EAP Type Values (RFC 3748 §5) ----

const (
	EAPTypeIdentity uint8 = 1
	EAPTypeNotify   uint8 = 2
	EAPTypeNAK      uint8 = 3
	EAPTypeMSCHAPv2 uint8 = 26 // RFC 2759 / RFC 2548
	EAPTypeTLS      uint8 = 13 // RFC 5216
	EAPTypeExpanded uint8 = 254
)

// EAPPacket represents a parsed EAP (Extensible Authentication Protocol) packet.
//
// RFC 3748 §4:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|     Code      |  Identifier   |            Length             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|     Type      |  Type-Data ...
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
type EAPPacket struct {
	Code       uint8
	Identifier uint8
	Type       uint8  // Only for Request/Response (Code 1 or 2)
	Data       []byte // Type-specific data (after Type byte)
}

// ParseEAPPacket parses a raw EAP packet from the EAP payload data.
// The data parameter is the complete EAP message including Code/Identifier/Length.
func ParseEAPPacket(data []byte) (*EAPPacket, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("EAP packet too short: %d bytes", len(data))
	}

	pkt := &EAPPacket{
		Code:       data[0],
		Identifier: data[1],
	}

	length := binary.BigEndian.Uint16(data[2:4])
	if int(length) > len(data) {
		return nil, fmt.Errorf("EAP length %d exceeds data size %d", length, len(data))
	}

	if length < 4 {
		return nil, fmt.Errorf("EAP length %d too small", length)
	}

	// Success and Failure have no Type or Data fields.
	if pkt.Code == EAPCodeSuccess || pkt.Code == EAPCodeFailure {
		return pkt, nil
	}

	// Request and Response must have at least a Type byte.
	if length < 5 {
		return nil, fmt.Errorf("EAP Request/Response too short: length %d", length)
	}

	pkt.Type = data[4]

	if length > 5 {
		pkt.Data = cloneBytes(data[5:length])
	}

	return pkt, nil
}

// Marshal serializes the EAP packet into wire format.
func (p *EAPPacket) Marshal() []byte {
	if p.Code == EAPCodeSuccess || p.Code == EAPCodeFailure {
		buf := make([]byte, 4)
		buf[0] = p.Code
		buf[1] = p.Identifier

		binary.BigEndian.PutUint16(buf[2:4], 4)

		return buf
	}

	totalLen := 5 + len(p.Data) // Code(1) + ID(1) + Length(2) + Type(1) + Data
	buf := make([]byte, totalLen)
	buf[0] = p.Code
	buf[1] = p.Identifier

	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))

	buf[4] = p.Type

	if len(p.Data) > 0 {
		copy(buf[5:], p.Data)
	}

	return buf
}

// BuildEAPIdentityRequest builds an EAP-Identity request packet.
// RFC 3748 §5.1.
func BuildEAPIdentityRequest(id uint8) []byte {
	pkt := &EAPPacket{
		Code:       EAPCodeRequest,
		Identifier: id,
		Type:       EAPTypeIdentity,
	}

	return pkt.Marshal()
}

// BuildEAPSuccess builds an EAP-Success packet.
func BuildEAPSuccess(id uint8) []byte {
	return (&EAPPacket{
		Code:       EAPCodeSuccess,
		Identifier: id,
	}).Marshal()
}

// BuildEAPFailure builds an EAP-Failure packet.
func BuildEAPFailure(id uint8) []byte {
	return (&EAPPacket{
		Code:       EAPCodeFailure,
		Identifier: id,
	}).Marshal()
}

// ParseEAPIdentityResponse extracts the identity string from an EAP-Identity response.
func ParseEAPIdentityResponse(pkt *EAPPacket) (string, error) {
	if pkt.Code != EAPCodeResponse || pkt.Type != EAPTypeIdentity {
		return "", fmt.Errorf("not an EAP-Identity response: code=%d type=%d", pkt.Code, pkt.Type)
	}

	return string(pkt.Data), nil
}
