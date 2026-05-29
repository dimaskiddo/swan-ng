package l2tp

import (
	"encoding/binary"
	"testing"
)

func TestParseHeader_ControlMessage(t *testing.T) {
	// Build a control header: T=1, L=1, S=1, Ver=2.
	// flags(2) + length(2) + tunnelID(2) + sessionID(2) + Ns(2) + Nr(2) = 12 bytes.
	buf := make([]byte, 12)
	flags := flagType | flagLength | flagSequence | version2
	binary.BigEndian.PutUint16(buf[0:2], flags)
	binary.BigEndian.PutUint16(buf[2:4], 12)  // length = 12 (no payload)
	binary.BigEndian.PutUint16(buf[4:6], 100) // tunnel ID
	binary.BigEndian.PutUint16(buf[6:8], 200) // session ID
	binary.BigEndian.PutUint16(buf[8:10], 5)  // Ns
	binary.BigEndian.PutUint16(buf[10:12], 3) // Nr

	hdr, payload, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if !hdr.IsControl {
		t.Error("expected IsControl=true")
	}
	if !hdr.HasLength {
		t.Error("expected HasLength=true")
	}
	if !hdr.HasSequence {
		t.Error("expected HasSequence=true")
	}
	if hdr.TunnelID != 100 {
		t.Errorf("TunnelID: got %d, want 100", hdr.TunnelID)
	}
	if hdr.SessionID != 200 {
		t.Errorf("SessionID: got %d, want 200", hdr.SessionID)
	}
	if hdr.Ns != 5 {
		t.Errorf("Ns: got %d, want 5", hdr.Ns)
	}
	if hdr.Nr != 3 {
		t.Errorf("Nr: got %d, want 3", hdr.Nr)
	}
	if len(payload) != 0 {
		t.Errorf("payload length: got %d, want 0", len(payload))
	}
}

func TestParseHeader_DataMessage(t *testing.T) {
	// Build a minimal data header: T=0, Ver=2. No L, no S.
	// flags(2) + tunnelID(2) + sessionID(2) = 6 bytes + 4 bytes payload.
	buf := make([]byte, 10)
	flags := version2 // T=0, L=0, S=0
	binary.BigEndian.PutUint16(buf[0:2], flags)
	binary.BigEndian.PutUint16(buf[2:4], 42) // tunnel ID
	binary.BigEndian.PutUint16(buf[4:6], 99) // session ID
	// payload: 4 bytes
	buf[6] = 0xAA
	buf[7] = 0xBB
	buf[8] = 0xCC
	buf[9] = 0xDD

	hdr, payload, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}
	if hdr.IsControl {
		t.Error("expected IsControl=false for data message")
	}
	if hdr.TunnelID != 42 {
		t.Errorf("TunnelID: got %d, want 42", hdr.TunnelID)
	}
	if hdr.SessionID != 99 {
		t.Errorf("SessionID: got %d, want 99", hdr.SessionID)
	}
	if len(payload) != 4 {
		t.Errorf("payload length: got %d, want 4", len(payload))
	}
	if payload[0] != 0xAA || payload[3] != 0xDD {
		t.Errorf("payload mismatch: got %x", payload)
	}
}

func TestParseHeader_TooShort(t *testing.T) {
	_, _, err := ParseHeader([]byte{0x00, 0x02})
	if err == nil {
		t.Error("expected error for too-short packet")
	}
}

func TestParseHeader_BadVersion(t *testing.T) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], 0x0003) // version 3
	_, _, err := ParseHeader(buf)
	if err == nil {
		t.Error("expected error for bad version")
	}
}

func TestParseHeader_ControlMissingFlags(t *testing.T) {
	// Control message (T=1) without L and S bits — should error.
	buf := make([]byte, 8)
	flags := flagType | version2 // T=1 but no L/S
	binary.BigEndian.PutUint16(buf[0:2], flags)
	binary.BigEndian.PutUint16(buf[2:4], 10)
	binary.BigEndian.PutUint16(buf[4:6], 0)
	binary.BigEndian.PutUint16(buf[6:8], 0)

	_, _, err := ParseHeader(buf)
	if err == nil {
		t.Error("expected error for control message missing L/S bits")
	}
}

func TestSerializeHeader_RoundTrip(t *testing.T) {
	// Serialize a control header and parse it back.
	original := &Header{
		IsControl:   true,
		HasLength:   true,
		HasSequence: true,
		Length:      12,
		TunnelID:    500,
		SessionID:   0,
		Ns:          7,
		Nr:          3,
	}

	data := SerializeHeader(original)
	parsed, _, err := ParseHeader(data)
	if err != nil {
		t.Fatalf("round-trip parse failed: %v", err)
	}
	if parsed.TunnelID != original.TunnelID {
		t.Errorf("TunnelID mismatch: got %d, want %d", parsed.TunnelID, original.TunnelID)
	}
	if parsed.Ns != original.Ns {
		t.Errorf("Ns mismatch: got %d, want %d", parsed.Ns, original.Ns)
	}
	if parsed.Nr != original.Nr {
		t.Errorf("Nr mismatch: got %d, want %d", parsed.Nr, original.Nr)
	}
}

func TestBuildControlHeader(t *testing.T) {
	hdr := BuildControlHeader(10, 0, 1, 2, 0)
	parsed, _, err := ParseHeader(hdr)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !parsed.IsControl {
		t.Error("expected control message")
	}
	if parsed.TunnelID != 10 {
		t.Errorf("TunnelID: got %d, want 10", parsed.TunnelID)
	}
	if parsed.Ns != 1 {
		t.Errorf("Ns: got %d, want 1", parsed.Ns)
	}
	if parsed.Nr != 2 {
		t.Errorf("Nr: got %d, want 2", parsed.Nr)
	}
}

func TestBuildZLB(t *testing.T) {
	zlb := BuildZLB(50, 3, 4)
	parsed, payload, err := ParseHeader(zlb)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if !parsed.IsControl {
		t.Error("ZLB should be a control message")
	}
	if parsed.TunnelID != 50 {
		t.Errorf("TunnelID: got %d, want 50", parsed.TunnelID)
	}
	if len(payload) != 0 {
		t.Errorf("ZLB should have empty payload, got %d bytes", len(payload))
	}
}

func TestBuildDataHeader(t *testing.T) {
	hdr := BuildDataHeader(10, 20)
	parsed, _, err := ParseHeader(hdr)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.IsControl {
		t.Error("expected data message")
	}
	if parsed.TunnelID != 10 {
		t.Errorf("TunnelID: got %d, want 10", parsed.TunnelID)
	}
	if parsed.SessionID != 20 {
		t.Errorf("SessionID: got %d, want 20", parsed.SessionID)
	}
}

// --- AVP Tests ---

func TestParseAVPs_MessageType(t *testing.T) {
	// Build a Message Type AVP (Mandatory, IETF, Type=0, Value=1 SCCRQ).
	avp := NewMessageTypeAVP(MsgSCCRQ)
	data := SerializeAVP(avp)

	parsed, err := ParseAVPs(data)
	if err != nil {
		t.Fatalf("ParseAVPs failed: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 AVP, got %d", len(parsed))
	}
	if !parsed[0].Mandatory {
		t.Error("expected Mandatory=true")
	}
	if parsed[0].VendorID != 0 {
		t.Errorf("VendorID: got %d, want 0", parsed[0].VendorID)
	}
	if parsed[0].AttrType != AVPMessageType {
		t.Errorf("AttrType: got %d, want %d", parsed[0].AttrType, AVPMessageType)
	}

	msgType := GetMessageType(parsed)
	if msgType != MsgSCCRQ {
		t.Errorf("MessageType: got %d, want %d", msgType, MsgSCCRQ)
	}
}

func TestSerializeAVPs_RoundTrip(t *testing.T) {
	avps := []AVP{
		NewMessageTypeAVP(MsgSCCRP),
		NewProtocolVersionAVP(),
		NewHostNameAVP("test-server"),
		NewAssignedTunnelIDAVP(42),
		NewReceiveWindowSizeAVP(4),
	}

	data := SerializeAVPs(avps)
	parsed, err := ParseAVPs(data)
	if err != nil {
		t.Fatalf("ParseAVPs round-trip failed: %v", err)
	}
	if len(parsed) != len(avps) {
		t.Fatalf("AVP count: got %d, want %d", len(parsed), len(avps))
	}

	// Verify message type.
	msgType := GetMessageType(parsed)
	if msgType != MsgSCCRP {
		t.Errorf("MessageType: got %d, want %d", msgType, MsgSCCRP)
	}

	// Verify tunnel ID.
	tid, ok := GetAVPUint16(parsed, AVPAssignedTunnelID)
	if !ok || tid != 42 {
		t.Errorf("AssignedTunnelID: got %d, want 42 (found=%v)", tid, ok)
	}

	// Verify hostname.
	hn, ok := GetAVPString(parsed, AVPHostName)
	if !ok || hn != "test-server" {
		t.Errorf("HostName: got %q, want %q (found=%v)", hn, "test-server", ok)
	}
}

func TestParseAVPs_Malformed(t *testing.T) {
	// AVP with length < minimum header.
	data := []byte{0x80, 0x03, 0x00, 0x00, 0x00, 0x00} // length=3 < 6
	_, err := ParseAVPs(data)
	if err == nil {
		t.Error("expected error for malformed AVP length")
	}
}

func TestGetAVPUint32(t *testing.T) {
	avp := NewFramingCapAVP()
	data := SerializeAVP(avp)
	parsed, err := ParseAVPs(data)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}

	val, ok := GetAVPUint32(parsed, AVPFramingCap)
	if !ok {
		t.Fatal("FramingCap not found")
	}
	if val != 0x00000003 {
		t.Errorf("FramingCap: got 0x%08X, want 0x00000003", val)
	}
}

func TestNewResultCodeAVP(t *testing.T) {
	avp := NewResultCodeAVP(1, 0, "")
	if !avp.Mandatory {
		t.Error("ResultCode should be mandatory")
	}
	if len(avp.Value) != 2 {
		t.Errorf("ResultCode value length: got %d, want 2", len(avp.Value))
	}
	rc := binary.BigEndian.Uint16(avp.Value[0:2])
	if rc != 1 {
		t.Errorf("ResultCode: got %d, want 1", rc)
	}

	avpWithMsg := NewResultCodeAVP(2, 6, "error occurred")
	if len(avpWithMsg.Value) != 4+len("error occurred") {
		t.Errorf("ResultCode with msg: got len %d, want %d", len(avpWithMsg.Value), 4+len("error occurred"))
	}
}

// --- Sequence Number Tests ---

func TestSeqLessThan(t *testing.T) {
	tests := []struct {
		a, b uint16
		want bool
	}{
		{0, 1, true},
		{1, 0, false},
		{0, 0, false},
		{65535, 0, true},  // wrap-around
		{0, 65535, false}, // reverse wrap
		{100, 200, true},
		{200, 100, false},
		{32767, 32768, true},
		{32768, 32767, false},
	}

	for _, tt := range tests {
		got := seqLessThan(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("seqLessThan(%d, %d) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}
