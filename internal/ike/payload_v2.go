package ike

import (
	"encoding/binary"
	"fmt"
)

// ---- IKEv2 Notify Message Types (RFC 7296 §3.10.1) ----

// NotifyType identifies IKEv2 notification message types.
type NotifyType uint16

const (
	// Error notifications (1-16383).
	NotifyUnsupportedCriticalPayload NotifyType = 1
	NotifyInvalidIKESPI              NotifyType = 4
	NotifyInvalidMajorVersion        NotifyType = 5
	NotifyInvalidSyntax              NotifyType = 7
	NotifyInvalidMessageID           NotifyType = 9
	NotifyInvalidSPI                 NotifyType = 11
	NotifyNoProposalChosen           NotifyType = 14
	NotifyInvalidKEPayload           NotifyType = 17
	NotifyAuthenticationFailed       NotifyType = 24
	NotifySinglePairRequired         NotifyType = 34
	NotifyNoAdditionalSAS            NotifyType = 35
	NotifyInternalAddressFailure     NotifyType = 36
	NotifyFailedCPRequired           NotifyType = 37
	NotifyTSUnacceptable             NotifyType = 38
	NotifyInvalidSelectors           NotifyType = 39
	NotifyTemporaryFailure           NotifyType = 43
	NotifyChildSANotFound            NotifyType = 44

	// Status notifications (16384-65535).
	NotifyInitialContact              NotifyType = 16384
	NotifySetWindowSize               NotifyType = 16385
	NotifyAdditionalTSPossible        NotifyType = 16386
	NotifyIPCOMPSupported             NotifyType = 16387
	NotifyNATDetectionSourceIP        NotifyType = 16388
	NotifyNATDetectionDestIP          NotifyType = 16389
	NotifyCookie                      NotifyType = 16390
	NotifyUseTransportMode            NotifyType = 16391
	NotifyHTTPCertLookupSupported     NotifyType = 16392
	NotifyRekeyingSA                  NotifyType = 16393
	NotifyESPTFCPaddingNotSupported   NotifyType = 16394
	NotifyNonFirstFragmentsAlso       NotifyType = 16395
	NotifyMOBIKESupported             NotifyType = 16396 // RFC 4555
	NotifyAdditionalIP4Address        NotifyType = 16397
	NotifyAdditionalIP6Address        NotifyType = 16398
	NotifyNoAdditionalAddresses       NotifyType = 16399
	NotifyUpdateSAAddresses           NotifyType = 16400 // RFC 4555
	NotifyCookie2                     NotifyType = 16401 // RFC 4555
	NotifyNoNATSFound                 NotifyType = 16402
	NotifyIKEv2FragmentationSupported NotifyType = 16430 // RFC 7383
	NotifySignatureHashAlgorithms     NotifyType = 16431
)

// ---- IKEv2 ID Types (RFC 7296 §3.5) ----

// IDType identifies the type of IKE identity.
type IDType uint8

const (
	IDIPv4Addr   IDType = 1
	IDFQDN       IDType = 2
	IDRfc822Addr IDType = 3 // Email address
	IDIPv6Addr   IDType = 5
	IDDerASN1DN  IDType = 9  // X.500 Distinguished Name
	IDDerASN1GN  IDType = 10 // X.500 General Name
	IDKeyID      IDType = 11
)

// ---- IKEv2 Auth Methods (RFC 7296 §3.8) ----

// AuthMethod identifies the authentication method in AUTH payload.
type AuthMethod uint8

const (
	AuthRSASig      AuthMethod = 1  // RSA Digital Signature
	AuthSharedKey   AuthMethod = 2  // Shared Key Message Integrity Code (PSK)
	AuthDSSSig      AuthMethod = 3  // DSS Digital Signature
	AuthECDSASHA256 AuthMethod = 9  // ECDSA with SHA-256 on P-256
	AuthECDSASHA384 AuthMethod = 10 // ECDSA with SHA-384 on P-384
	AuthECDSASHA512 AuthMethod = 11 // ECDSA with SHA-512 on P-521
	AuthDigitalSig  AuthMethod = 14 // Digital Signature (RFC 7427)
)

// ---- IKEv2 Certificate Encoding (RFC 7296 §3.6) ----

// CertEncoding identifies the certificate encoding type.
type CertEncoding uint8

const (
	CertPKCS7Wrapped     CertEncoding = 1
	CertPGP              CertEncoding = 2
	CertDNSSigned        CertEncoding = 3
	CertX509Sig          CertEncoding = 4 // X.509 Certificate - Signature
	CertKerberosToken    CertEncoding = 6
	CertCRL              CertEncoding = 7
	CertARL              CertEncoding = 8
	CertSPKI             CertEncoding = 9
	CertX509Attr         CertEncoding = 10
	CertRawRSA           CertEncoding = 11
	CertHashAndURLX509   CertEncoding = 12
	CertHashAndURLBundle CertEncoding = 13
)

// ---- IKEv2 Configuration Payload Types (RFC 7296 §3.15) ----

// CPType identifies configuration payload exchange type.
type CPType uint8

const (
	CPRequest CPType = 1
	CPReply   CPType = 2
	CPSet     CPType = 3
	CPAck     CPType = 4
)

// ConfigAttrType identifies configuration attribute types.
type ConfigAttrType uint16

const (
	ConfigInternalIP4Address  ConfigAttrType = 1
	ConfigInternalIP4Netmask  ConfigAttrType = 2
	ConfigInternalIP4DNS      ConfigAttrType = 3
	ConfigInternalIP4NBNS     ConfigAttrType = 4
	ConfigInternalIP4DHCP     ConfigAttrType = 6
	ConfigApplicationVersion  ConfigAttrType = 7
	ConfigInternalIP6Address  ConfigAttrType = 8
	ConfigInternalIP6DNS      ConfigAttrType = 10
	ConfigInternalIP4Subnet   ConfigAttrType = 13
	ConfigSupportedAttributes ConfigAttrType = 14
	ConfigInternalIP6Subnet   ConfigAttrType = 15
)

// ---- IKEv2 Traffic Selector Types (RFC 7296 §3.13.1) ----

// TSType identifies traffic selector type.
type TSType uint8

const (
	TSIPv4AddrRange TSType = 7
	TSIPv6AddrRange TSType = 8
)

// ---- IKEv2 Protocol IDs (RFC 7296 §3.3.1) ----

// ProtocolID identifies IPsec protocol in proposals.
type ProtocolID uint8

const (
	ProtocolIKE ProtocolID = 1
	ProtocolAH  ProtocolID = 2
	ProtocolESP ProtocolID = 3
)

// ---- IKEv2 Payload Structures ----

// KEPayload represents the Key Exchange payload (RFC 7296 §3.4).
type KEPayload struct {
	DHGroup uint16
	Data    []byte // Public DH value
}

func (p *KEPayload) Type() PayloadType { return PayloadKE }
func (p *KEPayload) Marshal() ([]byte, error) {
	body := make([]byte, 4+len(p.Data))
	binary.BigEndian.PutUint16(body[0:2], p.DHGroup)

	// bytes 2-3 reserved
	copy(body[4:], p.Data)

	return marshalWithHeader(p.Type(), body), nil
}

// NoncePayload represents the Nonce payload (RFC 7296 §3.9).
type NoncePayload struct {
	NonceData []byte // 16-256 bytes per RFC 7296
}

func (p *NoncePayload) Type() PayloadType { return PayloadNonce }
func (p *NoncePayload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.NonceData), nil
}

// IDPayload represents the Identification payload (RFC 7296 §3.5).
type IDPayload struct {
	IsInitiator bool // true = IDi (35), false = IDr (36)
	IDType      IDType
	Data        []byte // Identity data
}

func (p *IDPayload) Type() PayloadType {
	if p.IsInitiator {
		return PayloadIDi
	}

	return PayloadIDr
}

func (p *IDPayload) Marshal() ([]byte, error) {
	body := make([]byte, 4+len(p.Data))
	body[0] = byte(p.IDType)

	// bytes 1-3 reserved
	copy(body[4:], p.Data)

	return marshalWithHeader(p.Type(), body), nil
}

// CERTPayload represents the Certificate payload (RFC 7296 §3.6).
type CERTPayload struct {
	Encoding CertEncoding
	Data     []byte // Certificate data
}

func (p *CERTPayload) Type() PayloadType { return PayloadCERT }
func (p *CERTPayload) Marshal() ([]byte, error) {
	body := make([]byte, 1+len(p.Data))
	body[0] = byte(p.Encoding)
	copy(body[1:], p.Data)
	return marshalWithHeader(p.Type(), body), nil
}

// CERTREQPayload represents the Certificate Request payload (RFC 7296 §3.7).
type CERTREQPayload struct {
	Encoding CertEncoding
	Data     []byte // Certification authority data
}

func (p *CERTREQPayload) Type() PayloadType { return PayloadCERTREQ }
func (p *CERTREQPayload) Marshal() ([]byte, error) {
	body := make([]byte, 1+len(p.Data))
	body[0] = byte(p.Encoding)

	copy(body[1:], p.Data)

	return marshalWithHeader(p.Type(), body), nil
}

// AUTHPayload represents the Authentication payload (RFC 7296 §3.8).
type AUTHPayload struct {
	Method AuthMethod
	Data   []byte // Authentication data
}

func (p *AUTHPayload) Type() PayloadType { return PayloadAUTH }
func (p *AUTHPayload) Marshal() ([]byte, error) {
	body := make([]byte, 4+len(p.Data))
	body[0] = byte(p.Method)

	// bytes 1-3 reserved
	copy(body[4:], p.Data)

	return marshalWithHeader(p.Type(), body), nil
}

// NotifyPayload represents the Notify payload (RFC 7296 §3.10).
type NotifyPayload struct {
	ProtocolID    ProtocolID
	SPISize       uint8
	NotifyMsgType NotifyType
	SPI           []byte
	NotifyData    []byte
}

func (p *NotifyPayload) Type() PayloadType { return PayloadNotify }
func (p *NotifyPayload) Marshal() ([]byte, error) {
	body := make([]byte, 4+len(p.SPI)+len(p.NotifyData))
	body[0] = byte(p.ProtocolID)
	body[1] = byte(len(p.SPI))
	binary.BigEndian.PutUint16(body[2:4], uint16(p.NotifyMsgType))

	copy(body[4:], p.SPI)
	copy(body[4+len(p.SPI):], p.NotifyData)

	return marshalWithHeader(p.Type(), body), nil
}

// DeletePayload represents the Delete payload (RFC 7296 §3.11).
type DeletePayload struct {
	ProtocolID ProtocolID
	SPISize    uint8
	SPIs       [][]byte
}

func (p *DeletePayload) Type() PayloadType { return PayloadDelete }
func (p *DeletePayload) Marshal() ([]byte, error) {
	body := make([]byte, 4+len(p.SPIs)*int(p.SPISize))
	body[0] = byte(p.ProtocolID)
	body[1] = p.SPISize
	binary.BigEndian.PutUint16(body[2:4], uint16(len(p.SPIs)))
	offset := 4

	for _, spi := range p.SPIs {
		copy(body[offset:], spi)
		offset += int(p.SPISize)
	}

	return marshalWithHeader(p.Type(), body), nil
}

// VendorIDPayload represents the Vendor ID payload (RFC 7296 §3.12).
type VendorIDPayload struct {
	VendorData []byte
}

func (p *VendorIDPayload) Type() PayloadType { return PayloadVendorID }
func (p *VendorIDPayload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.VendorData), nil
}

// TrafficSelector represents a single traffic selector (RFC 7296 §3.13.1).
type TrafficSelector struct {
	TSType    TSType
	IPProtoID uint8
	StartPort uint16
	EndPort   uint16
	StartAddr []byte // 4 bytes for IPv4, 16 for IPv6
	EndAddr   []byte
}

// TSPayload represents the Traffic Selector payload (RFC 7296 §3.13).
type TSPayload struct {
	IsInitiator bool // true = TSi (44), false = TSr (45)
	Selectors   []TrafficSelector
}

func (p *TSPayload) Type() PayloadType {
	if p.IsInitiator {
		return PayloadTSi
	}

	return PayloadTSr
}

func (p *TSPayload) Marshal() ([]byte, error) {
	// Header: NumTS (1) + reserved (3)
	var selectorBytes []byte
	for _, ts := range p.Selectors {
		addrLen := len(ts.StartAddr)
		tsLen := 8 + addrLen*2 // TS header(8) + start_addr + end_addr
		tsBuf := make([]byte, tsLen)
		tsBuf[0] = byte(ts.TSType)
		tsBuf[1] = ts.IPProtoID
		binary.BigEndian.PutUint16(tsBuf[2:4], uint16(tsLen))
		binary.BigEndian.PutUint16(tsBuf[4:6], ts.StartPort)
		binary.BigEndian.PutUint16(tsBuf[6:8], ts.EndPort)
		copy(tsBuf[8:], ts.StartAddr)
		copy(tsBuf[8+addrLen:], ts.EndAddr)
		selectorBytes = append(selectorBytes, tsBuf...)
	}

	body := make([]byte, 4+len(selectorBytes))
	body[0] = byte(len(p.Selectors))
	copy(body[4:], selectorBytes)

	return marshalWithHeader(p.Type(), body), nil
}

// SKPayload represents the Encrypted and Authenticated payload (RFC 7296 §3.14).
// Contains the encrypted payload chain.
type SKPayload struct {
	EncryptedData []byte // IV + ciphertext + ICV
}

func (p *SKPayload) Type() PayloadType { return PayloadSK }
func (p *SKPayload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.EncryptedData), nil
}

// ConfigAttribute represents a single configuration attribute (RFC 7296 §3.15.1).
type ConfigAttribute struct {
	Type  ConfigAttrType
	Value []byte
}

// CPPayload represents the Configuration payload (RFC 7296 §3.15).
type CPPayload struct {
	ConfigType CPType
	Attributes []ConfigAttribute
}

func (p *CPPayload) Type() PayloadType { return PayloadCP }
func (p *CPPayload) Marshal() ([]byte, error) {
	var attrBytes []byte
	for _, attr := range p.Attributes {
		attrBuf := make([]byte, 4+len(attr.Value))
		binary.BigEndian.PutUint16(attrBuf[0:2], uint16(attr.Type))
		binary.BigEndian.PutUint16(attrBuf[2:4], uint16(len(attr.Value)))
		copy(attrBuf[4:], attr.Value)
		attrBytes = append(attrBytes, attrBuf...)
	}

	body := make([]byte, 4+len(attrBytes))
	body[0] = byte(p.ConfigType)
	copy(body[4:], attrBytes)

	return marshalWithHeader(p.Type(), body), nil
}

// EAPPayload represents the EAP payload (RFC 7296 §3.16).
type EAPPayload struct {
	Data []byte // Complete EAP message
}

func (p *EAPPayload) Type() PayloadType { return PayloadEAP }
func (p *EAPPayload) Marshal() ([]byte, error) {
	return marshalWithHeader(p.Type(), p.Data), nil
}

// ---- Helper ----

// marshalWithHeader prepends a generic payload header to body.
func marshalWithHeader(_ PayloadType, body []byte) []byte {
	totalLen := PayloadHeaderLen + len(body)
	buf := make([]byte, totalLen)
	buf[0] = byte(PayloadNone) // NextPayload set by MarshalPayloadChain

	// buf[1] = 0 (not critical)
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	copy(buf[PayloadHeaderLen:], body)

	return buf
}

// ---- IKEv2 Payload Parsers ----

// parseV2Payload parses an IKEv2 payload body based on its type.
func parseV2Payload(pt PayloadType, body []byte) (Payload, error) {
	switch pt {
	case PayloadKE:
		return parseV2KE(body)

	case PayloadNonce:
		return parseV2Nonce(body)

	case PayloadIDi, PayloadIDr:
		return parseV2ID(body, pt == PayloadIDi)

	case PayloadCERT:
		return parseV2Cert(body)

	case PayloadCERTREQ:
		return parseV2CertReq(body)

	case PayloadAUTH:
		return parseV2Auth(body)

	case PayloadNotify:
		return parseV2Notify(body)

	case PayloadDelete:
		return parseV2Delete(body)

	case PayloadVendorID:
		return &VendorIDPayload{VendorData: cloneBytes(body)}, nil

	case PayloadTSi, PayloadTSr:
		return parseV2TS(body, pt == PayloadTSi)

	case PayloadSK:
		return &SKPayload{EncryptedData: cloneBytes(body)}, nil

	case PayloadCP:
		return parseV2CP(body)

	case PayloadEAP:
		return &EAPPayload{Data: cloneBytes(body)}, nil

	case PayloadSA:
		return parseV2SA(body)

	default:
		return nil, fmt.Errorf("unrecognized IKEv2 payload type %d", pt)
	}
}

func parseV2KE(body []byte) (*KEPayload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("KE payload too short: %d", len(body))
	}

	return &KEPayload{
		DHGroup: binary.BigEndian.Uint16(body[0:2]),
		Data:    cloneBytes(body[4:]),
	}, nil
}

func parseV2Nonce(body []byte) (*NoncePayload, error) {
	return &NoncePayload{NonceData: cloneBytes(body)}, nil
}

func parseV2ID(body []byte, isInitiator bool) (*IDPayload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("ID payload too short: %d", len(body))
	}

	return &IDPayload{
		IsInitiator: isInitiator,
		IDType:      IDType(body[0]),
		Data:        cloneBytes(body[4:]),
	}, nil
}

func parseV2Cert(body []byte) (*CERTPayload, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("CERT payload too short: %d", len(body))
	}

	return &CERTPayload{
		Encoding: CertEncoding(body[0]),
		Data:     cloneBytes(body[1:]),
	}, nil
}

func parseV2CertReq(body []byte) (*CERTREQPayload, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("CERTREQ payload too short: %d", len(body))
	}

	return &CERTREQPayload{
		Encoding: CertEncoding(body[0]),
		Data:     cloneBytes(body[1:]),
	}, nil
}

func parseV2Auth(body []byte) (*AUTHPayload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("AUTH payload too short: %d", len(body))
	}

	return &AUTHPayload{
		Method: AuthMethod(body[0]),
		Data:   cloneBytes(body[4:]),
	}, nil
}

func parseV2Notify(body []byte) (*NotifyPayload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("Notify payload too short: %d", len(body))
	}
	protocolID := ProtocolID(body[0])
	spiSize := body[1]
	msgType := NotifyType(binary.BigEndian.Uint16(body[2:4]))

	if int(4+spiSize) > len(body) {
		return nil, fmt.Errorf("Notify SPI extends beyond payload")
	}

	var spi []byte
	if spiSize > 0 {
		spi = cloneBytes(body[4 : 4+spiSize])
	}

	var notifyData []byte
	if int(4+spiSize) < len(body) {
		notifyData = cloneBytes(body[4+spiSize:])
	}

	return &NotifyPayload{
		ProtocolID:    protocolID,
		SPISize:       spiSize,
		NotifyMsgType: msgType,
		SPI:           spi,
		NotifyData:    notifyData,
	}, nil
}

func parseV2Delete(body []byte) (*DeletePayload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("Delete payload too short: %d", len(body))
	}
	protocolID := ProtocolID(body[0])
	spiSize := body[1]
	numSPIs := binary.BigEndian.Uint16(body[2:4])

	expectedLen := 4 + int(numSPIs)*int(spiSize)
	if len(body) < expectedLen {
		return nil, fmt.Errorf("Delete payload truncated: need %d, got %d",
			expectedLen, len(body))
	}

	var spis [][]byte
	offset := 4
	for i := 0; i < int(numSPIs); i++ {
		spis = append(spis, cloneBytes(body[offset:offset+int(spiSize)]))
		offset += int(spiSize)
	}

	return &DeletePayload{
		ProtocolID: protocolID,
		SPISize:    spiSize,
		SPIs:       spis,
	}, nil
}

func parseV2TS(body []byte, isInitiator bool) (*TSPayload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("TS payload too short: %d", len(body))
	}
	numTS := int(body[0])
	var selectors []TrafficSelector
	offset := 4

	for i := 0; i < numTS; i++ {
		if offset+8 > len(body) {
			return nil, fmt.Errorf("TS selector %d header truncated", i)
		}

		tsType := TSType(body[offset])
		ipProto := body[offset+1]
		selectorLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		startPort := binary.BigEndian.Uint16(body[offset+4 : offset+6])
		endPort := binary.BigEndian.Uint16(body[offset+6 : offset+8])

		if offset+selectorLen > len(body) {
			return nil, fmt.Errorf("TS selector %d extends beyond payload", i)
		}

		addrLen := (selectorLen - 8) / 2
		startAddr := cloneBytes(body[offset+8 : offset+8+addrLen])
		endAddr := cloneBytes(body[offset+8+addrLen : offset+8+addrLen*2])

		selectors = append(selectors, TrafficSelector{
			TSType:    tsType,
			IPProtoID: ipProto,
			StartPort: startPort,
			EndPort:   endPort,
			StartAddr: startAddr,
			EndAddr:   endAddr,
		})

		offset += selectorLen
	}

	return &TSPayload{
		IsInitiator: isInitiator,
		Selectors:   selectors,
	}, nil
}

func parseV2CP(body []byte) (*CPPayload, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("CP payload too short: %d", len(body))
	}
	cpType := CPType(body[0])

	var attrs []ConfigAttribute
	offset := 4
	for offset+4 <= len(body) {
		attrType := ConfigAttrType(binary.BigEndian.Uint16(body[offset : offset+2]))
		attrLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		if offset+4+attrLen > len(body) {
			break
		}
		attrs = append(attrs, ConfigAttribute{
			Type:  attrType,
			Value: cloneBytes(body[offset+4 : offset+4+attrLen]),
		})
		offset += 4 + attrLen
	}

	return &CPPayload{
		ConfigType: cpType,
		Attributes: attrs,
	}, nil
}
