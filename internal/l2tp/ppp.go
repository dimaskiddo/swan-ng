package l2tp

import (
	"encoding/binary"
	"fmt"
)

// PPP protocol numbers (RFC 1661 §2).
const (
	// PPPProtoIPv4 is the PPP protocol number for IPv4 datagrams.
	PPPProtoIPv4 uint16 = 0x0021
	// PPPProtoIPv6 is the PPP protocol number for IPv6 datagrams.
	PPPProtoIPv6 uint16 = 0x0057
	// PPPProtoIPCP is the PPP protocol number for IP Control Protocol (RFC 1332).
	PPPProtoIPCP uint16 = 0x8021
	// PPPProtoIPv6CP is the PPP protocol number for IPv6 Control Protocol.
	PPPProtoIPv6CP uint16 = 0x8057
	// PPPProtoCCP is the PPP protocol number for Compression Control Protocol.
	PPPProtoCCP uint16 = 0x80FD
	// PPPProtoLCP is the PPP protocol number for Link Control Protocol (RFC 1661).
	PPPProtoLCP uint16 = 0xC021
	// PPPProtoPAP is the PPP protocol number for Password Authentication Protocol.
	PPPProtoPAP uint16 = 0xC023
	// PPPProtoCHAP is the PPP protocol number for Challenge Handshake Authentication Protocol (RFC 1994).
	PPPProtoCHAP uint16 = 0xC223
)

// PPP Address and Control field constants (RFC 1661 §2).
const (
	// pppAddress is the All-Stations address (0xFF).
	pppAddress byte = 0xFF
	// pppControl is the Unnumbered Information command (0x03).
	pppControl byte = 0x03
)

// PPPFrame represents a parsed PPP frame as received inside L2TP.
// In L2TP, PPP frames are carried without HDLC framing or FCS.
// The frame may optionally omit Address/Control fields (ACFC - RFC 1661 §6.6).
type PPPFrame struct {
	// Protocol identifies the encapsulated protocol (e.g., LCP, CHAP, IPCP, IPv4).
	Protocol uint16
	// Payload is the information field contents.
	Payload []byte
}

// ParsePPPFrame parses a PPP frame from L2TP data payload.
// Handles Address/Control Field Compression (ACFC) per RFC 1661 §6.6:
// if the first byte is not 0xFF (All-Stations), ACFC is in use and
// the frame starts directly with the Protocol field.
func ParsePPPFrame(data []byte) (*PPPFrame, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("ppp: frame too short (%d bytes)", len(data))
	}

	offset := 0

	// Check for Address/Control field.
	// If first byte is 0xFF, both Address (0xFF) and Control (0x03) are present.
	if data[0] == pppAddress {
		if len(data) < 4 {
			return nil, fmt.Errorf("ppp: frame too short for address+control (%d bytes)", len(data))
		}

		if data[1] != pppControl {
			return nil, fmt.Errorf("ppp: unexpected control byte 0x%02X (expected 0x03)", data[1])
		}

		offset = 2
	}

	// Parse Protocol field.
	// Protocol field compression (PFC - RFC 1661 §6.5): if bit 0 of first byte
	// is 1, protocol is 1 byte. Otherwise 2 bytes.
	remaining := data[offset:]
	if len(remaining) < 1 {
		return nil, fmt.Errorf("ppp: missing protocol field")
	}

	var proto uint16
	if remaining[0]&0x01 != 0 {
		// Protocol Field Compression: single byte protocol.
		proto = uint16(remaining[0])
		offset++
	} else {
		if len(remaining) < 2 {
			return nil, fmt.Errorf("ppp: truncated 2-byte protocol field")
		}

		proto = binary.BigEndian.Uint16(remaining[0:2])
		offset += 2
	}

	return &PPPFrame{
		Protocol: proto,
		Payload:  data[offset:],
	}, nil
}

// SerializePPPFrame builds a raw PPP frame with Address/Control fields.
// This creates the standard uncompressed format.
func SerializePPPFrame(proto uint16, payload []byte) []byte {
	// Address(1) + Control(1) + Protocol(2) + payload.
	frame := make([]byte, 4+len(payload))

	frame[0] = pppAddress
	frame[1] = pppControl

	binary.BigEndian.PutUint16(frame[2:4], proto)

	if len(payload) > 0 {
		copy(frame[4:], payload)
	}

	return frame
}

// SerializePPPFrameCompact builds a PPP frame without Address/Control fields (ACFC).
// Some implementations prefer this compact format.
func SerializePPPFrameCompact(proto uint16, payload []byte) []byte {
	// Protocol(2) + payload.
	frame := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], proto)

	if len(payload) > 0 {
		copy(frame[2:], payload)
	}

	return frame
}
