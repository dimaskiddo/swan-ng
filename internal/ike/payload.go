package ike

import (
	"encoding/binary"
	"fmt"
)

// PayloadType identifies the type of an IKE payload.
type PayloadType uint8

// IKEv1 payload types (RFC 2408 §3.1).
const (
	PayloadNoneV1      PayloadType = 0
	PayloadSAV1        PayloadType = 1
	PayloadProposalV1  PayloadType = 2
	PayloadTransformV1 PayloadType = 3
	PayloadKEV1        PayloadType = 4
	PayloadIDV1        PayloadType = 5
	PayloadCERTV1      PayloadType = 6
	PayloadCERTREQV1   PayloadType = 7
	PayloadHashV1      PayloadType = 8
	PayloadSIGV1       PayloadType = 9
	PayloadNonceV1     PayloadType = 10
	PayloadNotifyV1    PayloadType = 11
	PayloadDeleteV1    PayloadType = 12
	PayloadVendorIDV1  PayloadType = 13
	PayloadNATDV1      PayloadType = 20 // NAT-D (RFC 3947)
	PayloadNATOAV1     PayloadType = 21 // NAT-OA (RFC 3947)
)

// IKEv2 payload types (RFC 7296 §3.2).
const (
	PayloadNone     PayloadType = 0
	PayloadSA       PayloadType = 33
	PayloadKE       PayloadType = 34
	PayloadIDi      PayloadType = 35
	PayloadIDr      PayloadType = 36
	PayloadCERT     PayloadType = 37
	PayloadCERTREQ  PayloadType = 38
	PayloadAUTH     PayloadType = 39
	PayloadNonce    PayloadType = 40
	PayloadNotify   PayloadType = 41
	PayloadDelete   PayloadType = 42
	PayloadVendorID PayloadType = 43
	PayloadTSi      PayloadType = 44
	PayloadTSr      PayloadType = 45
	PayloadSK       PayloadType = 46
	PayloadCP       PayloadType = 47
	PayloadEAP      PayloadType = 48
	PayloadSKF      PayloadType = 53 // Encrypted Fragment (RFC 7383)
)

// String returns a human-readable payload type name.
func (pt PayloadType) String() string {
	switch pt {
	case PayloadNone:
		return "None"

	case PayloadSAV1:
		return "SA (v1)"

	case PayloadProposalV1:
		return "Proposal (v1)"

	case PayloadTransformV1:
		return "Transform (v1)"

	case PayloadKEV1:
		return "KE (v1)"

	case PayloadIDV1:
		return "ID (v1)"

	case PayloadCERTV1:
		return "CERT (v1)"

	case PayloadCERTREQV1:
		return "CERTREQ (v1)"

	case PayloadHashV1:
		return "Hash (v1)"

	case PayloadSIGV1:
		return "SIG (v1)"

	case PayloadNonceV1:
		return "Nonce (v1)"

	case PayloadNotifyV1:
		return "Notify (v1)"

	case PayloadDeleteV1:
		return "Delete (v1)"

	case PayloadVendorIDV1:
		return "VendorID (v1)"

	case PayloadNATDV1:
		return "NAT-D (v1)"

	case PayloadNATOAV1:
		return "NAT-OA (v1)"

	case PayloadSA:
		return "SA"

	case PayloadKE:
		return "KE"

	case PayloadIDi:
		return "IDi"

	case PayloadIDr:
		return "IDr"

	case PayloadCERT:
		return "CERT"

	case PayloadCERTREQ:
		return "CERTREQ"

	case PayloadAUTH:
		return "AUTH"

	case PayloadNonce:
		return "Nonce"

	case PayloadNotify:
		return "Notify"

	case PayloadDelete:
		return "Delete"

	case PayloadVendorID:
		return "VendorID"

	case PayloadTSi:
		return "TSi"

	case PayloadTSr:
		return "TSr"

	case PayloadSK:
		return "SK"

	case PayloadCP:
		return "CP"

	case PayloadEAP:
		return "EAP"

	case PayloadSKF:
		return "SKF"

	default:
		return fmt.Sprintf("Unknown(%d)", pt)
	}
}

// PayloadHeaderLen is the size of the generic payload header (4 bytes).
// RFC 7296 §3.2, RFC 2408 §3.2.
const PayloadHeaderLen = 4

// GenericPayloadHeader is the 4-byte header prefixed to every IKE payload.
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	| Next Payload  |C|  RESERVED   |         Payload Length        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type GenericPayloadHeader struct {
	NextPayload PayloadType
	Critical    bool
	Length      uint16 // Total payload length including this 4-byte header
}

// ParseGenericPayloadHeader parses the 4-byte generic payload header.
func ParseGenericPayloadHeader(buf []byte) (GenericPayloadHeader, error) {
	if len(buf) < PayloadHeaderLen {
		return GenericPayloadHeader{}, fmt.Errorf(
			"buffer too short for payload header: need %d, got %d",
			PayloadHeaderLen, len(buf))
	}

	return GenericPayloadHeader{
		NextPayload: PayloadType(buf[0]),
		Critical:    buf[1]&0x80 != 0,
		Length:      binary.BigEndian.Uint16(buf[2:4]),
	}, nil
}

// Marshal writes the generic payload header into buf.
func (g GenericPayloadHeader) Marshal(buf []byte) error {
	if len(buf) < PayloadHeaderLen {
		return fmt.Errorf("buffer too short for payload header marshal: need %d, got %d",
			PayloadHeaderLen, len(buf))
	}

	buf[0] = byte(g.NextPayload)
	buf[1] = 0
	if g.Critical {
		buf[1] = 0x80
	}
	binary.BigEndian.PutUint16(buf[2:4], g.Length)

	return nil
}

// Payload is the interface implemented by all typed IKE payloads.
type Payload interface {
	Type() PayloadType
	Marshal() ([]byte, error)
}

// RawPayload holds an unparsed or unrecognized payload as raw bytes.
// Used for payloads we don't need to deeply inspect, or as fallback.
type RawPayload struct {
	PayloadType PayloadType
	Data        []byte // Payload body (excluding generic header)
}

// Type returns the payload type.
func (r *RawPayload) Type() PayloadType { return r.PayloadType }

// Marshal serializes the raw payload with its generic header.
func (r *RawPayload) Marshal() ([]byte, error) {
	totalLen := PayloadHeaderLen + len(r.Data)
	buf := make([]byte, totalLen)
	hdr := GenericPayloadHeader{
		NextPayload: PayloadNone,
		Length:      uint16(totalLen),
	}

	if err := hdr.Marshal(buf); err != nil {
		return nil, err
	}

	copy(buf[PayloadHeaderLen:], r.Data)
	return buf, nil
}

// ParsedPayload wraps a parsed payload with its generic header metadata.
type ParsedPayload struct {
	Header  GenericPayloadHeader
	Payload Payload
}

// PayloadChain represents an ordered list of parsed payloads from an IKE message.
type PayloadChain []ParsedPayload

// FindFirst returns the first payload of the given type, or nil if not found.
func (pc PayloadChain) FindFirst(pt PayloadType) Payload {
	for _, pp := range pc {
		if pp.Payload.Type() == pt {
			return pp.Payload
		}
	}

	return nil
}

// FindAll returns all payloads of the given type.
func (pc PayloadChain) FindAll(pt PayloadType) []Payload {
	var result []Payload
	for _, pp := range pc {
		if pp.Payload.Type() == pt {
			result = append(result, pp.Payload)
		}
	}

	return result
}

// ParsePayloadChain walks the payload chain starting from firstPayload type.
// buf should start immediately after the IKE header (offset 28).
// isV2 controls whether IKEv2 or IKEv1 payload type interpretation is used.
func ParsePayloadChain(buf []byte, firstPayload PayloadType, isV2 bool) (PayloadChain, error) {
	var chain PayloadChain
	nextType := firstPayload
	offset := 0

	for nextType != PayloadNone {
		if offset+PayloadHeaderLen > len(buf) {
			return chain, fmt.Errorf("payload chain truncated at offset %d", offset)
		}

		gph, err := ParseGenericPayloadHeader(buf[offset:])
		if err != nil {
			return chain, fmt.Errorf("parsing payload header at offset %d: %w", offset, err)
		}

		if gph.Length < PayloadHeaderLen {
			return chain, fmt.Errorf("invalid payload length %d at offset %d (min %d)",
				gph.Length, offset, PayloadHeaderLen)
		}

		endOffset := offset + int(gph.Length)
		if endOffset > len(buf) {
			return chain, fmt.Errorf("payload at offset %d extends beyond buffer (need %d, have %d)",
				offset, endOffset, len(buf))
		}

		// Extract payload body (after generic header).
		body := buf[offset+PayloadHeaderLen : endOffset]

		// Parse typed payload or fall back to RawPayload.
		payload := parseTypedPayload(nextType, body, isV2)

		chain = append(chain, ParsedPayload{
			Header:  gph,
			Payload: payload,
		})

		nextType = gph.NextPayload
		offset = endOffset
	}

	return chain, nil
}

// parseTypedPayload attempts to parse a specific payload type.
// Falls back to RawPayload on parse error or unrecognized type.
func parseTypedPayload(pt PayloadType, body []byte, isV2 bool) Payload {
	var parsed Payload
	var err error

	if isV2 {
		parsed, err = parseV2Payload(pt, body)
	} else {
		parsed, err = parseV1Payload(pt, body)
	}

	if err != nil || parsed == nil {
		return &RawPayload{PayloadType: pt, Data: cloneBytes(body)}
	}

	return parsed
}

// cloneBytes returns a copy of b.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}

	c := make([]byte, len(b))
	copy(c, b)

	return c
}

// MarshalPayloadChain serializes a list of payloads into a contiguous buffer
// with correct NextPayload chaining in each generic header.
func MarshalPayloadChain(payloads []Payload) ([]byte, PayloadType, error) {
	if len(payloads) == 0 {
		return nil, PayloadNone, nil
	}

	// First, marshal each payload to get its raw bytes.
	marshaled := make([][]byte, len(payloads))
	for i, p := range payloads {
		data, err := p.Marshal()
		if err != nil {
			return nil, PayloadNone, fmt.Errorf("marshaling payload %d (%s): %w", i, p.Type(), err)
		}

		marshaled[i] = data
	}

	// Calculate total size.
	totalSize := 0
	for _, m := range marshaled {
		totalSize += len(m)
	}

	// Assemble with correct NextPayload chaining.
	result := make([]byte, totalSize)
	offset := 0
	for i, m := range marshaled {
		copy(result[offset:], m)

		// Set NextPayload in each generic header to point to next payload type.
		if i < len(payloads)-1 {
			result[offset] = byte(payloads[i+1].Type())
		} else {
			result[offset] = byte(PayloadNone)
		}

		offset += len(m)
	}

	return result, payloads[0].Type(), nil
}

// Message represents a complete IKE message: header + payload chain.
type Message struct {
	Header     Header
	Payloads   PayloadChain
	RawMessage []byte // Pre-serialized message (used for encrypted IKEv1 messages)
}

// ParseMessage parses a complete IKE message from buf.
func ParseMessage(buf []byte) (*Message, error) {
	if len(buf) < HeaderLen {
		return nil, fmt.Errorf("buffer too short for IKE message: need %d, got %d", HeaderLen, len(buf))
	}

	hdr, err := ParseHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("parsing IKE header: %w", err)
	}

	if err := hdr.Validate(); err != nil {
		return nil, fmt.Errorf("invalid IKE header: %w", err)
	}

	msgLen := int(hdr.Length)
	if msgLen > len(buf) {
		return nil, fmt.Errorf("IKE message length %d exceeds buffer size %d", msgLen, len(buf))
	}

	isV2 := hdr.IsIKEv2()
	payloadBuf := buf[HeaderLen:msgLen]

	chain, err := ParsePayloadChain(payloadBuf, hdr.NextPayload, isV2)
	if err != nil {
		return nil, fmt.Errorf("parsing payload chain: %w", err)
	}

	return &Message{
		Header:   hdr,
		Payloads: chain,
	}, nil
}

// Marshal serializes the complete IKE message.
func (m *Message) Marshal() ([]byte, error) {
	// If pre-serialized (e.g., encrypted IKEv1 message), return directly.
	if len(m.RawMessage) > 0 {
		return m.RawMessage, nil
	}

	// Collect payloads as Payload interface slice.
	var payloadList []Payload
	for _, pp := range m.Payloads {
		payloadList = append(payloadList, pp.Payload)
	}

	payloadBytes, firstPayload, err := MarshalPayloadChain(payloadList)
	if err != nil {
		return nil, fmt.Errorf("marshaling payload chain: %w", err)
	}

	// Update header.
	m.Header.NextPayload = firstPayload
	m.Header.Length = uint32(HeaderLen + len(payloadBytes))

	buf := make([]byte, m.Header.Length)
	if err := m.Header.Marshal(buf); err != nil {
		return nil, fmt.Errorf("marshaling header: %w", err)
	}

	copy(buf[HeaderLen:], payloadBytes)

	return buf, nil
}
