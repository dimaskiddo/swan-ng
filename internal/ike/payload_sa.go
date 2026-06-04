package ike

import (
	"encoding/binary"
	"fmt"
)

// ---- IKEv1 Transform Attribute IDs (RFC 2409 §A) ----

const (
	V1AttrEncryptionAlg uint16 = 1
	V1AttrHashAlg       uint16 = 2
	V1AttrAuthMethod    uint16 = 3
	V1AttrGroupDesc     uint16 = 4
	V1AttrGroupType     uint16 = 5
	V1AttrLifeType      uint16 = 11
	V1AttrLifeDuration  uint16 = 12
	V1AttrKeyLength     uint16 = 14
)

// IKEv1 Encryption Algorithm IDs (RFC 2409 Appendix A)
const (
	V1EncrDES_CBC  uint16 = 1
	V1EncrIDEA_CBC uint16 = 2
	V1EncrBF_CBC   uint16 = 3
	V1EncrRC5_R16  uint16 = 4
	V1Encr3DES_CBC uint16 = 5
	V1EncrCAST_CBC uint16 = 6
	V1EncrAES_CBC  uint16 = 7
)

// IKEv1 Hash Algorithm IDs (RFC 2409 Appendix A)
const (
	V1HashMD5    uint16 = 1
	V1HashSHA1   uint16 = 2
	V1HashTIGER  uint16 = 3
	V1HashSHA256 uint16 = 4
	V1HashSHA384 uint16 = 5
	V1HashSHA512 uint16 = 6
)

// IKEv1 Authentication Method IDs (RFC 2409 Appendix A)
const (
	V1AuthPreSharedKey uint16 = 1
	V1AuthDSS_Sig      uint16 = 2
	V1AuthRSA_Sig      uint16 = 3
	V1AuthRSA_Enc      uint16 = 4
	V1AuthRSA_RevEnc   uint16 = 5
)

// IKEv1 XAUTH Authentication Method IDs (draft-ietf-ipsec-isakmp-xauth-06)
const (
	V1AuthXAUTH_InitPSK uint16 = 65001
	V1AuthXAUTH_RespPSK uint16 = 65005
	V1AuthXAUTH_InitRSA uint16 = 65003
	V1AuthXAUTH_RespRSA uint16 = 65007
)

// XAUTH attribute type IDs (draft-ietf-ipsec-isakmp-xauth-06 §6).
const (
	XAUTH_TYPE          uint16 = 16520
	XAUTH_USER_NAME     uint16 = 16521
	XAUTH_USER_PASSWORD uint16 = 16522
	XAUTH_PASSCODE      uint16 = 16523
	XAUTH_MESSAGE       uint16 = 16528
	XAUTH_CHALLENGE     uint16 = 16529
	XAUTH_DOMAIN        uint16 = 16530
	XAUTH_STATUS        uint16 = 16527
)

// IKEv1 Life Type values.
const (
	V1LifeTypeSeconds uint16 = 1
	V1LifeTypeKB      uint16 = 2
)

// IKEv1 IPsec Transform IDs for ESP (RFC 2407 §4.4.4).
const (
	V1ESPTransformDES  uint8 = 2
	V1ESPTransform3DES uint8 = 3
	V1ESPTransformAES  uint8 = 12
	V1ESPTransformNULL uint8 = 11
)

// IKEv1 IPsec Auth Algorithm for Phase 2 (RFC 2407 §4.5).
const (
	V1IPsecAuthHMAC_MD5    uint16 = 1
	V1IPsecAuthHMAC_SHA1   uint16 = 2
	V1IPsecAuthHMAC_SHA256 uint16 = 5
)

// IKEv1 Phase 2 attribute types (RFC 2407 §4.5).
const (
	V1P2AttrLifeType     uint16 = 1
	V1P2AttrLifeDuration uint16 = 2
	V1P2AttrGroupDesc    uint16 = 3
	V1P2AttrEncapMode    uint16 = 4
	V1P2AttrAuthAlg      uint16 = 5
	V1P2AttrKeyLength    uint16 = 6
)

// IKEv1 Encapsulation modes (RFC 2407 §4.5).
const (
	V1EncapTunnel    uint16 = 1
	V1EncapTransport uint16 = 2

	// NAT-T encapsulation modes (RFC 3947).
	V1EncapUDPTunnel    uint16 = 3
	V1EncapUDPTransport uint16 = 4
)

// ---- IKEv2 Transform Types (RFC 7296 §3.3.2) ----

// TransformType identifies the type of an IKEv2 cryptographic transform.
type TransformType uint8

const (
	TransformTypeENCR TransformType = 1 // Encryption Algorithm
	TransformTypePRF  TransformType = 2 // Pseudo-Random Function
	TransformTypeINTG TransformType = 3 // Integrity Algorithm
	TransformTypeDH   TransformType = 4 // Diffie-Hellman Group
	TransformTypeESN  TransformType = 5 // Extended Sequence Numbers
)

// ---- IKEv2 Encryption Transform IDs (RFC 7296 §3.3.2) ----

const (
	EncrDES_IV64   uint16 = 1
	EncrDES        uint16 = 2
	Encr3DES       uint16 = 3
	EncrRC5        uint16 = 4
	EncrIDEA       uint16 = 5
	EncrCAST       uint16 = 6
	EncrBLOWFISH   uint16 = 7
	Encr3IDEA      uint16 = 8
	EncrAES_CBC    uint16 = 12
	EncrAES_CTR    uint16 = 13
	EncrAES_CCM_8  uint16 = 14
	EncrAES_CCM_12 uint16 = 15
	EncrAES_CCM_16 uint16 = 16
	EncrAES_GCM_8  uint16 = 18
	EncrAES_GCM_12 uint16 = 19
	EncrAES_GCM_16 uint16 = 20 // AES-GCM with 16-octet ICV
	EncrCHACHA20   uint16 = 28 // ChaCha20-Poly1305 (RFC 7634)
)

// ---- IKEv2 PRF Transform IDs ----

const (
	PRFHMAC_MD5    uint16 = 1
	PRFHMAC_SHA1   uint16 = 2
	PRFHMAC_TIGER  uint16 = 3
	PRFAES128_XCBC uint16 = 4
	PRFHMAC_SHA256 uint16 = 5
	PRFHMAC_SHA384 uint16 = 6
	PRFHMAC_SHA512 uint16 = 7
)

// ---- IKEv2 Integrity Transform IDs ----

const (
	AuthNone            uint16 = 0
	AuthHMAC_MD5_96     uint16 = 1
	AuthHMAC_SHA1_96    uint16 = 2
	AuthDES_MAC         uint16 = 3
	AuthKPDK_MD5        uint16 = 4
	AuthAES_XCBC_96     uint16 = 5
	AuthHMAC_MD5_128    uint16 = 6
	AuthHMAC_SHA1_160   uint16 = 7
	AuthAES_CMAC_96     uint16 = 8
	AuthAES_128_GMAC    uint16 = 9
	AuthAES_192_GMAC    uint16 = 10
	AuthAES_256_GMAC    uint16 = 11
	AuthHMAC_SHA256_128 uint16 = 12
	AuthHMAC_SHA384_192 uint16 = 13
	AuthHMAC_SHA512_256 uint16 = 14
)

// ---- IKEv2 DH Group IDs ----

const (
	DHNone    uint16 = 0
	DHGroup1  uint16 = 1  // 768-bit MODP
	DHGroup2  uint16 = 2  // 1024-bit MODP
	DHGroup5  uint16 = 5  // 1536-bit MODP
	DHGroup14 uint16 = 14 // 2048-bit MODP
	DHGroup15 uint16 = 15 // 3072-bit MODP
	DHGroup16 uint16 = 16 // 4096-bit MODP
	DHGroup19 uint16 = 19 // 256-bit ECP (P-256)
	DHGroup20 uint16 = 20 // 384-bit ECP (P-384)
	DHGroup21 uint16 = 21 // 521-bit ECP (P-521)
)

// ---- IKEv2 ESN values ----

const (
	ESNNone uint16 = 0 // No ESN
	ESNYes  uint16 = 1 // ESN enabled
)

// ---- Transform Attribute Types (RFC 7296 §3.3.5) ----

const (
	// AttrKeyLength is the Key Length attribute (TV format, type 14).
	AttrKeyLength uint16 = 14
)

// ---- IKEv2 SA Payload Structures ----

// Transform represents a single IKEv2 cryptographic transform (RFC 7296 §3.3.2).
type Transform struct {
	Type      TransformType
	ID        uint16
	KeyLength uint16 // 0 if not applicable (set via attribute)
	IsLast    bool   // true if this is the last transform in proposal
}

// Proposal represents a single IKEv2 proposal (RFC 7296 §3.3.1).
type Proposal struct {
	Number     uint8
	ProtocolID ProtocolID
	SPI        []byte
	Transforms []Transform
	IsLast     bool // true if this is the last proposal in SA
}

// SAPayload represents the IKEv2 Security Association payload (RFC 7296 §3.3).
type SAPayload struct {
	Proposals []Proposal
}

func (p *SAPayload) Type() PayloadType {
	return PayloadSA
}

func (p *SAPayload) Marshal() ([]byte, error) {
	var proposalBytes []byte

	for i, prop := range p.Proposals {
		propData := marshalV2Proposal(&prop, i == len(p.Proposals)-1)
		proposalBytes = append(proposalBytes, propData...)
	}

	return marshalWithHeader(PayloadSA, proposalBytes), nil
}

// marshalV2Proposal serializes a single IKEv2 proposal sub-structure.
func marshalV2Proposal(prop *Proposal, isLast bool) []byte {
	// Marshal transforms first.
	var xformBytes []byte
	for i, xf := range prop.Transforms {
		xfData := marshalV2Transform(&xf, i == len(prop.Transforms)-1)
		xformBytes = append(xformBytes, xfData...)
	}

	// Proposal sub-structure header:
	// | LastOrMore(1) | Reserved(1) | ProposalLength(2) |
	// | ProposalNum(1) | ProtocolID(1) | SPISize(1) | NumTransforms(1) |
	// | SPI (variable) | Transforms... |
	spiSize := len(prop.SPI)
	propLen := 8 + spiSize + len(xformBytes)
	buf := make([]byte, propLen)

	if isLast {
		buf[0] = 0 // Last proposal
	} else {
		buf[0] = 2 // More proposals follow
	}
	// buf[1] = 0 // Reserved
	binary.BigEndian.PutUint16(buf[2:4], uint16(propLen))
	buf[4] = prop.Number
	buf[5] = byte(prop.ProtocolID)
	buf[6] = byte(spiSize)
	buf[7] = byte(len(prop.Transforms))

	copy(buf[8:], prop.SPI)
	copy(buf[8+spiSize:], xformBytes)

	return buf
}

// marshalV2Transform serializes a single IKEv2 transform sub-structure.
func marshalV2Transform(xf *Transform, isLast bool) []byte {
	// Transform sub-structure header:
	// | LastOrMore(1) | Reserved(1) | TransformLength(2) |
	// | TransformType(1) | Reserved(1) | TransformID(2) |
	// | Attributes... |

	var attrBytes []byte
	if xf.KeyLength > 0 {
		// Key Length attribute in TV format: type(2) | value(2)
		attr := make([]byte, 4)
		binary.BigEndian.PutUint16(attr[0:2], AttrKeyLength|0x8000) // TV format bit
		binary.BigEndian.PutUint16(attr[2:4], xf.KeyLength)
		attrBytes = attr
	}

	xfLen := 8 + len(attrBytes)
	buf := make([]byte, xfLen)

	if isLast {
		buf[0] = 0 // Last transform
	} else {
		buf[0] = 3 // More transforms follow
	}
	// buf[1] = 0 // Reserved
	binary.BigEndian.PutUint16(buf[2:4], uint16(xfLen))
	buf[4] = byte(xf.Type)
	// buf[5] = 0 // Reserved
	binary.BigEndian.PutUint16(buf[6:8], xf.ID)

	copy(buf[8:], attrBytes)

	return buf
}

// ---- IKEv2 SA Parser ----

func parseV2SA(body []byte) (*SAPayload, error) {
	sa := &SAPayload{}
	offset := 0

	for offset < len(body) {
		if offset+8 > len(body) {
			return sa, fmt.Errorf("SA proposal header truncated at offset %d", offset)
		}

		lastOrMore := body[offset]
		propLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		propNum := body[offset+4]
		protocolID := ProtocolID(body[offset+5])
		spiSize := int(body[offset+6])
		numTransforms := int(body[offset+7])

		if propLen < 8 || offset+propLen > len(body) {
			return sa, fmt.Errorf("SA proposal length invalid: %d at offset %d", propLen, offset)
		}

		var spi []byte
		if spiSize > 0 {
			if offset+8+spiSize > offset+propLen {
				return sa, fmt.Errorf("SA proposal SPI truncated")
			}

			spi = cloneBytes(body[offset+8 : offset+8+spiSize])
		}

		// Parse transforms.
		transforms := parseV2Transforms(body[offset+8+spiSize:offset+propLen], numTransforms)

		sa.Proposals = append(sa.Proposals, Proposal{
			Number:     propNum,
			ProtocolID: protocolID,
			SPI:        spi,
			Transforms: transforms,
			IsLast:     lastOrMore == 0,
		})

		if lastOrMore == 0 {
			break // Last proposal
		}

		offset += propLen
	}

	return sa, nil
}

func parseV2Transforms(buf []byte, count int) []Transform {
	var transforms []Transform
	offset := 0

	for i := 0; i < count && offset < len(buf); i++ {
		if offset+8 > len(buf) {
			break
		}

		lastOrMore := buf[offset]

		xfLen := int(binary.BigEndian.Uint16(buf[offset+2 : offset+4]))
		xfType := TransformType(buf[offset+4])
		xfID := binary.BigEndian.Uint16(buf[offset+6 : offset+8])

		if xfLen < 8 || offset+xfLen > len(buf) {
			break
		}

		// Parse attributes for key length.
		var keyLength uint16
		if xfLen > 8 {
			attrs := ParseISAKMPAttributes(buf[offset+8 : offset+xfLen])
			for _, attr := range attrs {
				if attr.Type == AttrKeyLength && attr.IsTV && len(attr.Value) >= 2 {
					keyLength = binary.BigEndian.Uint16(attr.Value)
				}
			}
		}

		transforms = append(transforms, Transform{
			Type:      xfType,
			ID:        xfID,
			KeyLength: keyLength,
			IsLast:    lastOrMore == 0,
		})

		if lastOrMore == 0 {
			break
		}

		offset += xfLen
	}

	return transforms
}
