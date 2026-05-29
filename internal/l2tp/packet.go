package l2tp

import (
	"encoding/binary"
	"fmt"
)

// L2TPv2 header flags (RFC 2661 §3.1).
const (
	// flagType indicates control (1) or data (0) message.
	flagType uint16 = 0x8000
	// flagLength indicates Length field is present.
	flagLength uint16 = 0x4000
	// flagSequence indicates Ns/Nr fields are present.
	flagSequence uint16 = 0x0800
	// flagOffset indicates Offset field is present.
	flagOffset uint16 = 0x0200
	// flagPriority indicates data message priority.
	flagPriority uint16 = 0x0100
	// versionMask extracts the version field (lower 4 bits).
	versionMask uint16 = 0x000F
	// version2 is the L2TPv2 version number.
	version2 uint16 = 0x0002
)

// L2TPv2 control message types (RFC 2661 §3.2).
const (
	MsgSCCRQ   uint16 = 1  // Start-Control-Connection-Request
	MsgSCCRP   uint16 = 2  // Start-Control-Connection-Reply
	MsgSCCCN   uint16 = 3  // Start-Control-Connection-Connected
	MsgStopCCN uint16 = 4  // Stop-Control-Connection-Notification
	MsgHello   uint16 = 6  // Hello (keepalive)
	MsgOCRQ    uint16 = 7  // Outgoing-Call-Request
	MsgOCRP    uint16 = 8  // Outgoing-Call-Reply
	MsgOCCN    uint16 = 9  // Outgoing-Call-Connected
	MsgICRQ    uint16 = 10 // Incoming-Call-Request
	MsgICRP    uint16 = 11 // Incoming-Call-Reply
	MsgICCN    uint16 = 12 // Incoming-Call-Connected
	MsgCDN     uint16 = 14 // Call-Disconnect-Notify
	MsgWEN     uint16 = 15 // WAN-Error-Notify
	MsgSLI     uint16 = 16 // Set-Link-Info
)

// AVP Attribute Types (RFC 2661 §4.4, IETF Vendor ID = 0).
const (
	AVPMessageType        uint16 = 0  // Message Type
	AVPResultCode         uint16 = 1  // Result Code
	AVPProtocolVersion    uint16 = 2  // Protocol Version
	AVPFramingCap         uint16 = 3  // Framing Capabilities
	AVPBearerCap          uint16 = 4  // Bearer Capabilities
	AVPTieBreaker         uint16 = 5  // Tie Breaker
	AVPFirmwareRevision   uint16 = 6  // Firmware Revision
	AVPHostName           uint16 = 7  // Host Name
	AVPVendorName         uint16 = 8  // Vendor Name
	AVPAssignedTunnelID   uint16 = 9  // Assigned Tunnel ID
	AVPReceiveWindowSize  uint16 = 10 // Receive Window Size
	AVPChallenge          uint16 = 11 // Challenge
	AVPChallengeResponse  uint16 = 13 // Challenge Response
	AVPAssignedSessionID  uint16 = 14 // Assigned Session ID
	AVPCallSerialNumber   uint16 = 15 // Call Serial Number
	AVPBearerType         uint16 = 18 // Bearer Type
	AVPFramingType        uint16 = 19 // Framing Type
	AVPCalledNumber       uint16 = 21 // Called Number
	AVPCallingNumber      uint16 = 22 // Calling Number
	AVPTxConnectSpeed     uint16 = 24 // (Tx) Connect Speed BPS
	AVPPhysicalChannelID  uint16 = 25 // Physical Channel ID
	AVPInitialRecvLCPConf uint16 = 26 // Initial Received LCP CONFREQ
	AVPLastSentLCPConf    uint16 = 27 // Last Sent LCP CONFREQ
	AVPLastRecvLCPConf    uint16 = 28 // Last Received LCP CONFREQ
	AVPProxyAuthenType    uint16 = 29 // Proxy Authen Type
	AVPProxyAuthenName    uint16 = 30 // Proxy Authen Name
	AVPProxyAuthenChall   uint16 = 31 // Proxy Authen Challenge
	AVPProxyAuthenID      uint16 = 32 // Proxy Authen ID
	AVPProxyAuthenResp    uint16 = 33 // Proxy Authen Response
	AVPCallErrors         uint16 = 34 // Call Errors
	AVPRandomVector       uint16 = 36 // Random Vector
	AVPPrivateGroupID     uint16 = 37 // Private Group ID
	AVPRxConnectSpeed     uint16 = 38 // Rx Connect Speed
	AVPSequencingRequired uint16 = 39 // Sequencing Required
)

// Header represents an L2TPv2 message header (RFC 2661 §3.1).
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           Tunnel ID           |           Session ID          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|             Ns (opt)          |             Nr (opt)          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Header struct {
	// IsControl indicates a control message (T=1) vs data (T=0).
	IsControl bool
	// HasLength indicates the Length field is present.
	HasLength bool
	// HasSequence indicates Ns/Nr fields are present.
	HasSequence bool
	// HasOffset indicates the Offset field is present.
	HasOffset bool
	// Priority indicates data message priority.
	Priority bool
	// Length is total message length (when HasLength=true).
	Length uint16
	// TunnelID is the tunnel identifier (of the intended recipient).
	TunnelID uint16
	// SessionID is the session identifier (of the intended recipient).
	SessionID uint16
	// Ns is the sequence number of this message.
	Ns uint16
	// Nr is the expected next sequence number from the peer.
	Nr uint16
}

// minControlHeaderLen is the minimum size of an L2TPv2 control header.
// flags(2) + length(2) + tunnelID(2) + sessionID(2) + Ns(2) + Nr(2) = 12.
const minControlHeaderLen = 12

// minDataHeaderLen is the minimum size of an L2TPv2 data header.
// flags(2) + tunnelID(2) + sessionID(2) = 6.
const minDataHeaderLen = 6

// ParseHeader parses an L2TPv2 header from raw data.
// Returns the parsed header and the payload (everything after the header).
// For control messages, the payload contains AVPs.
// For data messages, the payload contains a PPP frame.
func ParseHeader(data []byte) (*Header, []byte, error) {
	if len(data) < minDataHeaderLen {
		return nil, nil, fmt.Errorf("l2tp: packet too short (%d bytes)", len(data))
	}

	flags := binary.BigEndian.Uint16(data[0:2])

	// Verify version = 2.
	ver := flags & versionMask
	if ver != version2 {
		return nil, nil, fmt.Errorf("l2tp: unsupported version %d (expected 2)", ver)
	}

	hdr := &Header{
		IsControl:   flags&flagType != 0,
		HasLength:   flags&flagLength != 0,
		HasSequence: flags&flagSequence != 0,
		HasOffset:   flags&flagOffset != 0,
		Priority:    flags&flagPriority != 0,
	}

	// Control messages MUST have Length and Sequence (RFC 2661 §3.1).
	if hdr.IsControl {
		if !hdr.HasLength || !hdr.HasSequence {
			return nil, nil, fmt.Errorf("l2tp: control message missing required L/S bits")
		}
	}

	offset := 2 // past flags

	// Length field (if present).
	if hdr.HasLength {
		if len(data) < offset+2 {
			return nil, nil, fmt.Errorf("l2tp: truncated length field")
		}
		hdr.Length = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// Validate stated length against available data.
		if int(hdr.Length) > len(data) {
			return nil, nil, fmt.Errorf("l2tp: stated length %d exceeds packet size %d", hdr.Length, len(data))
		}
	}

	// Tunnel ID + Session ID.
	if len(data) < offset+4 {
		return nil, nil, fmt.Errorf("l2tp: truncated tunnel/session ID")
	}
	hdr.TunnelID = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2
	hdr.SessionID = binary.BigEndian.Uint16(data[offset : offset+2])
	offset += 2

	// Ns/Nr (if present).
	if hdr.HasSequence {
		if len(data) < offset+4 {
			return nil, nil, fmt.Errorf("l2tp: truncated Ns/Nr fields")
		}
		hdr.Ns = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
		hdr.Nr = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2
	}

	// Offset (if present) — skip past offset padding.
	if hdr.HasOffset {
		if len(data) < offset+2 {
			return nil, nil, fmt.Errorf("l2tp: truncated offset field")
		}
		offsetSize := binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2 + int(offsetSize)
	}

	// Determine payload boundary.
	end := len(data)
	if hdr.HasLength {
		end = int(hdr.Length)
	}

	if offset > end {
		return nil, nil, fmt.Errorf("l2tp: header overflows packet (header=%d, total=%d)", offset, end)
	}

	return hdr, data[offset:end], nil
}

// SerializeHeader builds a raw L2TPv2 header from a Header struct.
// Does not include payload — caller appends payload after.
func SerializeHeader(hdr *Header) []byte {
	var flags uint16 = version2

	if hdr.IsControl {
		flags |= flagType | flagLength | flagSequence
	}
	if hdr.HasLength {
		flags |= flagLength
	}
	if hdr.HasSequence {
		flags |= flagSequence
	}
	if hdr.HasOffset {
		flags |= flagOffset
	}
	if hdr.Priority {
		flags |= flagPriority
	}

	// Calculate header size.
	size := 2 // flags
	if flags&flagLength != 0 {
		size += 2 // length
	}
	size += 4 // tunnel ID + session ID
	if flags&flagSequence != 0 {
		size += 4 // Ns + Nr
	}

	buf := make([]byte, size)
	binary.BigEndian.PutUint16(buf[0:2], flags)

	offset := 2

	if flags&flagLength != 0 {
		// Length will be set by caller or updated after payload appended.
		// For now, put the header length as placeholder.
		binary.BigEndian.PutUint16(buf[offset:offset+2], hdr.Length)
		offset += 2
	}

	binary.BigEndian.PutUint16(buf[offset:offset+2], hdr.TunnelID)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:offset+2], hdr.SessionID)
	offset += 2

	if flags&flagSequence != 0 {
		binary.BigEndian.PutUint16(buf[offset:offset+2], hdr.Ns)
		offset += 2
		binary.BigEndian.PutUint16(buf[offset:offset+2], hdr.Nr)
	}

	return buf
}

// BuildControlHeader creates a complete L2TP control header with the given
// tunnel ID, session ID, and sequence numbers.
// Control messages always have T=1, L=1, S=1.
func BuildControlHeader(tunnelID, sessionID, ns, nr uint16, payloadLen int) []byte {
	totalLen := uint16(minControlHeaderLen + payloadLen)
	hdr := &Header{
		IsControl:   true,
		HasLength:   true,
		HasSequence: true,
		Length:      totalLen,
		TunnelID:    tunnelID,
		SessionID:   sessionID,
		Ns:          ns,
		Nr:          nr,
	}
	return SerializeHeader(hdr)
}

// BuildDataHeader creates an L2TP data header for the given tunnel/session.
// Data messages have T=0 and no mandatory fields beyond tunnel/session IDs.
func BuildDataHeader(tunnelID, sessionID uint16) []byte {
	hdr := &Header{
		IsControl: false,
		TunnelID:  tunnelID,
		SessionID: sessionID,
	}
	return SerializeHeader(hdr)
}

// BuildZLB creates a Zero-Length Body acknowledgement message.
// ZLB is a control message with no AVP payload — used solely for ACKs.
// The Ns is NOT incremented for ZLB messages (RFC 2661 §5.8).
func BuildZLB(tunnelID, ns, nr uint16) []byte {
	return BuildControlHeader(tunnelID, 0, ns, nr, 0)
}

// AVP represents an L2TPv2 Attribute Value Pair (RFC 2661 §4.1).
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|M|H| rsvd  |     Length      |           Vendor ID           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|         Attribute Type        |        Attribute Value...
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type AVP struct {
	// Mandatory indicates the M-bit — unknown mandatory AVPs cause session/tunnel termination.
	Mandatory bool
	// Hidden indicates the H-bit — attribute value is hidden via shared secret.
	Hidden bool
	// VendorID is the IANA enterprise number (0 = IETF standard).
	VendorID uint16
	// AttrType is the attribute type within the vendor namespace.
	AttrType uint16
	// Value is the raw attribute value bytes.
	Value []byte
}

// avpHeaderLen is the fixed AVP header size: flags(2) + vendorID(2) + attrType(2) = 6.
const avpHeaderLen = 6

// AVP flag bits.
const (
	avpFlagMandatory uint16 = 0x8000
	avpFlagHidden    uint16 = 0x4000
	avpLengthMask    uint16 = 0x03FF // Lower 10 bits = length
)

// ParseAVPs parses all AVPs from a control message payload.
// Returns the list of parsed AVPs. Unknown non-mandatory AVPs are preserved.
// Malformed mandatory AVPs return an error.
func ParseAVPs(data []byte) ([]AVP, error) {
	var avps []AVP

	for len(data) >= avpHeaderLen {
		flagsLen := binary.BigEndian.Uint16(data[0:2])
		avpLen := int(flagsLen & avpLengthMask)

		if avpLen < avpHeaderLen {
			return nil, fmt.Errorf("l2tp: AVP length %d below minimum %d", avpLen, avpHeaderLen)
		}
		if avpLen > len(data) {
			return nil, fmt.Errorf("l2tp: AVP length %d exceeds remaining data %d", avpLen, len(data))
		}

		avp := AVP{
			Mandatory: flagsLen&avpFlagMandatory != 0,
			Hidden:    flagsLen&avpFlagHidden != 0,
			VendorID:  binary.BigEndian.Uint16(data[2:4]),
			AttrType:  binary.BigEndian.Uint16(data[4:6]),
		}

		if avpLen > avpHeaderLen {
			avp.Value = make([]byte, avpLen-avpHeaderLen)
			copy(avp.Value, data[avpHeaderLen:avpLen])
		}

		avps = append(avps, avp)
		data = data[avpLen:]
	}

	return avps, nil
}

// SerializeAVP serializes a single AVP to bytes.
func SerializeAVP(avp AVP) []byte {
	totalLen := avpHeaderLen + len(avp.Value)
	buf := make([]byte, totalLen)

	var flagsLen uint16 = uint16(totalLen) & avpLengthMask
	if avp.Mandatory {
		flagsLen |= avpFlagMandatory
	}
	if avp.Hidden {
		flagsLen |= avpFlagHidden
	}

	binary.BigEndian.PutUint16(buf[0:2], flagsLen)
	binary.BigEndian.PutUint16(buf[2:4], avp.VendorID)
	binary.BigEndian.PutUint16(buf[4:6], avp.AttrType)

	if len(avp.Value) > 0 {
		copy(buf[avpHeaderLen:], avp.Value)
	}

	return buf
}

// SerializeAVPs serializes a list of AVPs to bytes.
func SerializeAVPs(avps []AVP) []byte {
	var result []byte
	for _, avp := range avps {
		result = append(result, SerializeAVP(avp)...)
	}
	return result
}

// Helper functions for building common AVPs.

// NewMessageTypeAVP creates a mandatory Message Type AVP (Attribute 0).
func NewMessageTypeAVP(msgType uint16) AVP {
	val := make([]byte, 2)
	binary.BigEndian.PutUint16(val, msgType)
	return AVP{Mandatory: true, AttrType: AVPMessageType, Value: val}
}

// NewAssignedTunnelIDAVP creates a mandatory Assigned Tunnel ID AVP (Attribute 9).
func NewAssignedTunnelIDAVP(tunnelID uint16) AVP {
	val := make([]byte, 2)
	binary.BigEndian.PutUint16(val, tunnelID)
	return AVP{Mandatory: true, AttrType: AVPAssignedTunnelID, Value: val}
}

// NewAssignedSessionIDAVP creates a mandatory Assigned Session ID AVP (Attribute 14).
func NewAssignedSessionIDAVP(sessionID uint16) AVP {
	val := make([]byte, 2)
	binary.BigEndian.PutUint16(val, sessionID)
	return AVP{Mandatory: true, AttrType: AVPAssignedSessionID, Value: val}
}

// NewProtocolVersionAVP creates a mandatory Protocol Version AVP (Attribute 2).
// L2TPv2 = Version 1, Revision 0.
func NewProtocolVersionAVP() AVP {
	return AVP{Mandatory: true, AttrType: AVPProtocolVersion, Value: []byte{1, 0}}
}

// NewHostNameAVP creates a mandatory Host Name AVP (Attribute 7).
func NewHostNameAVP(hostname string) AVP {
	return AVP{Mandatory: true, AttrType: AVPHostName, Value: []byte(hostname)}
}

// NewVendorNameAVP creates a non-mandatory Vendor Name AVP (Attribute 8).
func NewVendorNameAVP(vendor string) AVP {
	return AVP{AttrType: AVPVendorName, Value: []byte(vendor)}
}

// NewFramingCapAVP creates a mandatory Framing Capabilities AVP (Attribute 3).
// Bits: A=async(bit 1), S=sync(bit 0). We advertise both.
func NewFramingCapAVP() AVP {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, 0x00000003) // A + S
	return AVP{Mandatory: true, AttrType: AVPFramingCap, Value: val}
}

// NewBearerCapAVP creates a mandatory Bearer Capabilities AVP (Attribute 4).
// Bits: A=analog(bit 1), D=digital(bit 0). We advertise both.
func NewBearerCapAVP() AVP {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, 0x00000003) // A + D
	return AVP{Mandatory: true, AttrType: AVPBearerCap, Value: val}
}

// NewReceiveWindowSizeAVP creates a mandatory Receive Window Size AVP (Attribute 10).
func NewReceiveWindowSizeAVP(windowSize uint16) AVP {
	val := make([]byte, 2)
	binary.BigEndian.PutUint16(val, windowSize)
	return AVP{Mandatory: true, AttrType: AVPReceiveWindowSize, Value: val}
}

// NewFirmwareRevisionAVP creates a non-mandatory Firmware Revision AVP (Attribute 6).
func NewFirmwareRevisionAVP(revision uint16) AVP {
	val := make([]byte, 2)
	binary.BigEndian.PutUint16(val, revision)
	return AVP{AttrType: AVPFirmwareRevision, Value: val}
}

// NewChallengeAVP creates a mandatory Challenge AVP (Attribute 11).
func NewChallengeAVP(challenge []byte) AVP {
	return AVP{Mandatory: true, AttrType: AVPChallenge, Value: challenge}
}

// NewChallengeResponseAVP creates a mandatory Challenge Response AVP (Attribute 13).
func NewChallengeResponseAVP(response []byte) AVP {
	return AVP{Mandatory: true, AttrType: AVPChallengeResponse, Value: response}
}

// NewResultCodeAVP creates a mandatory Result Code AVP (Attribute 1).
func NewResultCodeAVP(resultCode uint16, errorCode uint16, errorMsg string) AVP {
	size := 2 // result code
	if errorCode != 0 || errorMsg != "" {
		size += 2 // error code
	}
	size += len(errorMsg)

	val := make([]byte, size)
	binary.BigEndian.PutUint16(val[0:2], resultCode)
	if errorCode != 0 || errorMsg != "" {
		binary.BigEndian.PutUint16(val[2:4], errorCode)
		if errorMsg != "" {
			copy(val[4:], errorMsg)
		}
	}
	return AVP{Mandatory: true, AttrType: AVPResultCode, Value: val}
}

// NewCallSerialNumberAVP creates a mandatory Call Serial Number AVP (Attribute 15).
func NewCallSerialNumberAVP(serial uint32) AVP {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, serial)
	return AVP{Mandatory: true, AttrType: AVPCallSerialNumber, Value: val}
}

// NewFramingTypeAVP creates a mandatory Framing Type AVP (Attribute 19).
// Bits: A=async(bit 1), S=sync(bit 0).
func NewFramingTypeAVP(async, sync bool) AVP {
	var v uint32
	if async {
		v |= 0x00000002
	}
	if sync {
		v |= 0x00000001
	}
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, v)
	return AVP{Mandatory: true, AttrType: AVPFramingType, Value: val}
}

// NewTxConnectSpeedAVP creates a mandatory Tx Connect Speed AVP (Attribute 24).
func NewTxConnectSpeedAVP(bps uint32) AVP {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, bps)
	return AVP{Mandatory: true, AttrType: AVPTxConnectSpeed, Value: val}
}

// GetMessageType extracts the Message Type from a list of AVPs.
// Returns 0 if not found.
func GetMessageType(avps []AVP) uint16 {
	for _, avp := range avps {
		if avp.VendorID == 0 && avp.AttrType == AVPMessageType && len(avp.Value) >= 2 {
			return binary.BigEndian.Uint16(avp.Value)
		}
	}
	return 0
}

// GetAVPUint16 extracts a uint16 value from the first AVP matching the given attribute type.
// Returns (value, true) if found, (0, false) otherwise.
func GetAVPUint16(avps []AVP, attrType uint16) (uint16, bool) {
	for _, avp := range avps {
		if avp.VendorID == 0 && avp.AttrType == attrType && len(avp.Value) >= 2 {
			return binary.BigEndian.Uint16(avp.Value), true
		}
	}
	return 0, false
}

// GetAVPUint32 extracts a uint32 value from the first AVP matching the given attribute type.
// Returns (value, true) if found, (0, false) otherwise.
func GetAVPUint32(avps []AVP, attrType uint16) (uint32, bool) {
	for _, avp := range avps {
		if avp.VendorID == 0 && avp.AttrType == attrType && len(avp.Value) >= 4 {
			return binary.BigEndian.Uint32(avp.Value), true
		}
	}
	return 0, false
}

// GetAVPBytes extracts raw bytes from the first AVP matching the given attribute type.
// Returns (value, true) if found, (nil, false) otherwise.
func GetAVPBytes(avps []AVP, attrType uint16) ([]byte, bool) {
	for _, avp := range avps {
		if avp.VendorID == 0 && avp.AttrType == attrType {
			return avp.Value, true
		}
	}
	return nil, false
}

// GetAVPString extracts a string from the first AVP matching the given attribute type.
// Returns (value, true) if found, ("", false) otherwise.
func GetAVPString(avps []AVP, attrType uint16) (string, bool) {
	v, ok := GetAVPBytes(avps, attrType)
	if !ok {
		return "", false
	}
	return string(v), true
}
