package ike

import (
	"encoding/binary"
	"fmt"
)

// ---- IKEv1 DOI & Situation (RFC 2407, RFC 2408) ----

const (
	// DOIIPsec is the IANA DOI for IPsec (RFC 2407).
	DOIIPsec uint32 = 1

	// SituationIdentityOnly is the base situation for ISAKMP Phase 1.
	SituationIdentityOnly uint32 = 1
)

// ---- IKEv1 Payload Structures ----

// SAv1Payload represents the IKEv1 SA payload (RFC 2408 §3.4).
// Contains DOI, Situation, and nested Proposal payloads.
type SAv1Payload struct {
	DOI       uint32
	Situation uint32
	Proposals []ProposalV1Payload
}

func (p *SAv1Payload) Type() PayloadType {
	return PayloadSAV1
}

func (p *SAv1Payload) Marshal() ([]byte, error) {
	// Marshal proposals as a sub-chain.
	var propBytes []byte
	for i, prop := range p.Proposals {
		propData, err := prop.marshalBody()
		if err != nil {
			return nil, fmt.Errorf("marshaling proposal %d: %w", i, err)
		}

		propBuf := make([]byte, PayloadHeaderLen+len(propData))
		nextPL := PayloadNoneV1
		if i < len(p.Proposals)-1 {
			nextPL = PayloadProposalV1
		}

		hdr := GenericPayloadHeader{
			NextPayload: nextPL,
			Length:      uint16(PayloadHeaderLen + len(propData)),
		}

		if err := hdr.Marshal(propBuf); err != nil {
			return nil, err
		}

		copy(propBuf[PayloadHeaderLen:], propData)
		propBytes = append(propBytes, propBuf...)
	}

	// SA body: DOI(4) + Situation(4) + proposals
	body := make([]byte, 8+len(propBytes))

	binary.BigEndian.PutUint32(body[0:4], p.DOI)
	binary.BigEndian.PutUint32(body[4:8], p.Situation)

	copy(body[8:], propBytes)

	return marshalWithHeader(p.Type(), body), nil
}

// ProposalV1Payload represents an IKEv1 Proposal payload (RFC 2408 §3.5).
type ProposalV1Payload struct {
	Number     uint8
	ProtocolID ProtocolID
	SPI        []byte
	Transforms []TransformV1Payload
}

func (p *ProposalV1Payload) marshalBody() ([]byte, error) {
	// Marshal transforms as a sub-chain.
	var xformBytes []byte
	for i, xf := range p.Transforms {
		xfData, err := xf.marshalBody()
		if err != nil {
			return nil, fmt.Errorf("marshaling transform %d: %w", i, err)
		}

		xfBuf := make([]byte, PayloadHeaderLen+len(xfData))
		nextPL := PayloadNoneV1
		if i < len(p.Transforms)-1 {
			nextPL = PayloadTransformV1
		}

		hdr := GenericPayloadHeader{
			NextPayload: nextPL,
			Length:      uint16(PayloadHeaderLen + len(xfData)),
		}

		if err := hdr.Marshal(xfBuf); err != nil {
			return nil, err
		}

		copy(xfBuf[PayloadHeaderLen:], xfData)
		xformBytes = append(xformBytes, xfBuf...)
	}

	// Proposal body: Number(1) + ProtocolID(1) + SPISize(1) + NumTransforms(1) + SPI + transforms
	body := make([]byte, 4+len(p.SPI)+len(xformBytes))
	body[0] = p.Number
	body[1] = byte(p.ProtocolID)
	body[2] = byte(len(p.SPI))
	body[3] = byte(len(p.Transforms))

	copy(body[4:], p.SPI)
	copy(body[4+len(p.SPI):], xformBytes)

	return body, nil
}

// TransformV1Payload represents an IKEv1 Transform payload (RFC 2408 §3.6).
type TransformV1Payload struct {
	Number      uint8
	TransformID uint8
	Attributes  []ISAKMPAttribute
}

func (p *TransformV1Payload) marshalBody() ([]byte, error) {
	var attrBytes []byte
	for _, attr := range p.Attributes {
		attrBytes = append(attrBytes, attr.Marshal()...)
	}

	body := make([]byte, 4+len(attrBytes))
	body[0] = p.Number
	body[1] = p.TransformID

	// bytes 2-3 reserved
	copy(body[4:], attrBytes)

	return body, nil
}

// ISAKMPAttribute represents an ISAKMP Data Attribute (RFC 2408 §3.3).
// Supports both TV (Type/Value, 4 bytes) and TLV (Type/Length/Value) formats.
type ISAKMPAttribute struct {
	Type  uint16
	IsTV  bool   // true = Type/Value (2-byte value), false = TLV (variable length)
	Value []byte // 2 bytes for TV, variable for TLV
}

// Marshal serializes an ISAKMP attribute.
func (a ISAKMPAttribute) Marshal() []byte {
	if a.IsTV {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint16(buf[0:2], a.Type|0x8000) // Set AF bit for TV

		if len(a.Value) >= 2 {
			copy(buf[2:4], a.Value[:2])
		}

		return buf
	}

	buf := make([]byte, 4+len(a.Value))

	binary.BigEndian.PutUint16(buf[0:2], a.Type&0x7FFF) // Clear AF bit for TLV
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(a.Value)))

	copy(buf[4:], a.Value)

	return buf
}

// ParseISAKMPAttributes parses a sequence of ISAKMP attributes from buf.
func ParseISAKMPAttributes(buf []byte) []ISAKMPAttribute {
	var attrs []ISAKMPAttribute
	offset := 0

	for offset+4 <= len(buf) {
		typeField := binary.BigEndian.Uint16(buf[offset : offset+2])
		isTV := typeField&0x8000 != 0
		attrType := typeField & 0x7FFF

		if isTV {
			attrs = append(attrs, ISAKMPAttribute{
				Type:  attrType,
				IsTV:  true,
				Value: cloneBytes(buf[offset+2 : offset+4]),
			})
			offset += 4
		} else {
			attrLen := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
			if offset+4+attrLen > len(buf) {
				break
			}

			attrs = append(attrs, ISAKMPAttribute{
				Type:  attrType,
				IsTV:  false,
				Value: cloneBytes(buf[offset+4 : offset+4+attrLen]),
			})
			offset += 4 + attrLen
		}
	}

	return attrs
}

// ---- IKEv1-specific payload types ----

// HashV1Payload represents the IKEv1 Hash payload (RFC 2408 §3.11).
type HashV1Payload struct {
	HashData []byte
}

func (p *HashV1Payload) Type() PayloadType {
	return PayloadHashV1
}

func (p *HashV1Payload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.HashData), nil
}

// SIGv1Payload represents the IKEv1 Signature payload (RFC 2408 §3.12).
type SIGv1Payload struct {
	SigData []byte
}

func (p *SIGv1Payload) Type() PayloadType {
	return PayloadSIGV1
}

func (p *SIGv1Payload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.SigData), nil
}

// KEv1Payload represents the IKEv1 Key Exchange payload (RFC 2408 §3.6).
type KEv1Payload struct {
	Data []byte // Public DH value
}

func (p *KEv1Payload) Type() PayloadType {
	return PayloadKEV1
}

func (p *KEv1Payload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.Data), nil
}

// NonceV1Payload represents the IKEv1 Nonce payload (RFC 2408 §3.13).
type NonceV1Payload struct {
	NonceData []byte
}

func (p *NonceV1Payload) Type() PayloadType {
	return PayloadNonceV1
}

func (p *NonceV1Payload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.NonceData), nil
}

// IDv1Payload represents the IKEv1 Identification payload (RFC 2408 §3.8).
type IDv1Payload struct {
	IDType   IDType
	ProtoDOI uint8  // Protocol ID from DOI
	Port     uint16 // Port from DOI
	Data     []byte
}

func (p *IDv1Payload) Type() PayloadType {
	return PayloadIDV1
}

func (p *IDv1Payload) Marshal() ([]byte, error) {
	body := make([]byte, 4+len(p.Data))
	body[0] = byte(p.IDType)
	body[1] = p.ProtoDOI

	binary.BigEndian.PutUint16(body[2:4], p.Port)
	copy(body[4:], p.Data)

	return marshalWithHeader(p.Type(), body), nil
}

// NotifyV1Payload represents the IKEv1 Notification payload (RFC 2408 §3.14).
type NotifyV1Payload struct {
	DOI           uint32
	ProtocolID    ProtocolID
	SPISize       uint8
	NotifyMsgType uint16
	SPI           []byte
	NotifyData    []byte
}

func (p *NotifyV1Payload) Type() PayloadType {
	return PayloadNotifyV1
}

func (p *NotifyV1Payload) Marshal() ([]byte, error) {
	body := make([]byte, 8+len(p.SPI)+len(p.NotifyData))

	binary.BigEndian.PutUint32(body[0:4], p.DOI)

	body[4] = byte(p.ProtocolID)
	body[5] = byte(len(p.SPI))

	binary.BigEndian.PutUint16(body[6:8], p.NotifyMsgType)

	copy(body[8:], p.SPI)
	copy(body[8+len(p.SPI):], p.NotifyData)

	return marshalWithHeader(p.Type(), body), nil
}

// DeleteV1Payload represents the IKEv1 Delete payload (RFC 2408 §3.15).
type DeleteV1Payload struct {
	DOI        uint32
	ProtocolID ProtocolID
	SPISize    uint8
	SPIs       [][]byte
}

func (p *DeleteV1Payload) Type() PayloadType {
	return PayloadDeleteV1
}

func (p *DeleteV1Payload) Marshal() ([]byte, error) {
	body := make([]byte, 8+len(p.SPIs)*int(p.SPISize))

	binary.BigEndian.PutUint32(body[0:4], p.DOI)

	body[4] = byte(p.ProtocolID)
	body[5] = p.SPISize

	binary.BigEndian.PutUint16(body[6:8], uint16(len(p.SPIs)))
	offset := 8

	for _, spi := range p.SPIs {
		copy(body[offset:], spi)
		offset += int(p.SPISize)
	}

	return marshalWithHeader(p.Type(), body), nil
}

// NATDv1Payload represents the IKEv1 NAT-D payload (RFC 3947).
type NATDv1Payload struct {
	HashData []byte
}

func (p *NATDv1Payload) Type() PayloadType {
	return PayloadNATDV1
}

func (p *NATDv1Payload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.HashData), nil
}

// ---- IKEv1 Payload Parser ----

func parseV1Payload(pt PayloadType, body []byte) (Payload, error) {
	switch pt {
	case PayloadSAV1:
		return parseV1SA(body)

	case PayloadKEV1:
		return &KEv1Payload{Data: cloneBytes(body)}, nil

	case PayloadNonceV1:
		return &NonceV1Payload{NonceData: cloneBytes(body)}, nil

	case PayloadIDV1:
		return parseV1ID(body)

	case PayloadHashV1:
		return &HashV1Payload{HashData: cloneBytes(body)}, nil

	case PayloadSIGV1:
		return &SIGv1Payload{SigData: cloneBytes(body)}, nil

	case PayloadCERTV1:
		return parseV1Cert(body)

	case PayloadCERTREQV1:
		return parseV1CertReq(body)

	case PayloadNotifyV1:
		return parseV1Notify(body)

	case PayloadDeleteV1:
		return parseV1Delete(body)

	case PayloadVendorIDV1:
		return &VendorIDPayload{VendorData: cloneBytes(body)}, nil

	case PayloadNATDV1:
		return &NATDv1Payload{HashData: cloneBytes(body)}, nil

	default:
		return nil, fmt.Errorf("unrecognized IKEv1 payload type %d", pt)
	}
}

func parseV1SA(body []byte) (*SAv1Payload, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("SAv1 payload too short: %d", len(body))
	}

	sa := &SAv1Payload{
		DOI:       binary.BigEndian.Uint32(body[0:4]),
		Situation: binary.BigEndian.Uint32(body[4:8]),
	}

	// Parse nested proposal payloads.
	propBuf := body[8:]
	nextPL := PayloadProposalV1
	offset := 0

	for nextPL == PayloadProposalV1 && offset < len(propBuf) {
		if offset+PayloadHeaderLen > len(propBuf) {
			break
		}

		gph, err := ParseGenericPayloadHeader(propBuf[offset:])
		if err != nil {
			return sa, fmt.Errorf("parsing proposal header: %w", err)
		}

		if int(gph.Length) < PayloadHeaderLen || offset+int(gph.Length) > len(propBuf) {
			break
		}

		propBody := propBuf[offset+PayloadHeaderLen : offset+int(gph.Length)]
		prop, err := parseV1Proposal(propBody)
		if err != nil {
			return sa, fmt.Errorf("parsing proposal: %w", err)
		}

		sa.Proposals = append(sa.Proposals, *prop)
		nextPL = gph.NextPayload
		offset += int(gph.Length)
	}

	return sa, nil
}

func parseV1Proposal(body []byte) (*ProposalV1Payload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("proposal payload too short: %d", len(body))
	}

	prop := &ProposalV1Payload{
		Number:     body[0],
		ProtocolID: ProtocolID(body[1]),
	}
	spiSize := int(body[2])
	numTransforms := int(body[3])

	if len(body) < 4+spiSize {
		return nil, fmt.Errorf("proposal SPI truncated")
	}

	if spiSize > 0 {
		prop.SPI = cloneBytes(body[4 : 4+spiSize])
	}

	// Parse nested transform payloads.
	xformBuf := body[4+spiSize:]
	offset := 0

	for i := 0; i < numTransforms && offset < len(xformBuf); i++ {
		if offset+PayloadHeaderLen > len(xformBuf) {
			break
		}

		gph, err := ParseGenericPayloadHeader(xformBuf[offset:])
		if err != nil {
			break
		}

		if int(gph.Length) < PayloadHeaderLen || offset+int(gph.Length) > len(xformBuf) {
			break
		}

		xfBody := xformBuf[offset+PayloadHeaderLen : offset+int(gph.Length)]
		xf := parseV1Transform(xfBody)

		prop.Transforms = append(prop.Transforms, xf)
		offset += int(gph.Length)
	}

	_ = numTransforms // Used above in loop
	return prop, nil
}

func parseV1Transform(body []byte) TransformV1Payload {
	xf := TransformV1Payload{}
	if len(body) < 4 {
		return xf
	}
	xf.Number = body[0]
	xf.TransformID = body[1]
	xf.Attributes = ParseISAKMPAttributes(body[4:])

	return xf
}

func parseV1ID(body []byte) (*IDv1Payload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("IDv1 payload too short: %d", len(body))
	}

	return &IDv1Payload{
		IDType:   IDType(body[0]),
		ProtoDOI: body[1],
		Port:     binary.BigEndian.Uint16(body[2:4]),
		Data:     cloneBytes(body[4:]),
	}, nil
}

func parseV1Cert(body []byte) (*CERTPayload, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("CERTv1 payload too short")
	}

	return &CERTPayload{
		Encoding: CertEncoding(body[0]),
		Data:     cloneBytes(body[1:]),
	}, nil
}

func parseV1CertReq(body []byte) (*CERTREQPayload, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("CERTREQv1 payload too short")
	}

	return &CERTREQPayload{
		Encoding: CertEncoding(body[0]),
		Data:     cloneBytes(body[1:]),
	}, nil
}

func parseV1Notify(body []byte) (*NotifyV1Payload, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("NotifyV1 payload too short: %d", len(body))
	}

	doi := binary.BigEndian.Uint32(body[0:4])
	protocolID := ProtocolID(body[4])
	spiSize := body[5]
	msgType := binary.BigEndian.Uint16(body[6:8])

	if int(8+spiSize) > len(body) {
		return nil, fmt.Errorf("NotifyV1 SPI extends beyond payload")
	}

	var spi []byte
	if spiSize > 0 {
		spi = cloneBytes(body[8 : 8+spiSize])
	}

	var notifyData []byte
	if int(8+spiSize) < len(body) {
		notifyData = cloneBytes(body[8+spiSize:])
	}

	return &NotifyV1Payload{
		DOI:           doi,
		ProtocolID:    protocolID,
		SPISize:       spiSize,
		NotifyMsgType: msgType,
		SPI:           spi,
		NotifyData:    notifyData,
	}, nil
}

func parseV1Delete(body []byte) (*DeleteV1Payload, error) {
	if len(body) < 8 {
		return nil, fmt.Errorf("DeleteV1 payload too short: %d", len(body))
	}

	doi := binary.BigEndian.Uint32(body[0:4])
	protocolID := ProtocolID(body[4])
	spiSize := body[5]
	numSPIs := binary.BigEndian.Uint16(body[6:8])

	expectedLen := 8 + int(numSPIs)*int(spiSize)
	if len(body) < expectedLen {
		return nil, fmt.Errorf("DeleteV1 payload truncated")
	}

	var spis [][]byte
	offset := 8
	for i := 0; i < int(numSPIs); i++ {
		spis = append(spis, cloneBytes(body[offset:offset+int(spiSize)]))
		offset += int(spiSize)
	}

	return &DeleteV1Payload{
		DOI:        doi,
		ProtocolID: protocolID,
		SPISize:    spiSize,
		SPIs:       spis,
	}, nil
}
