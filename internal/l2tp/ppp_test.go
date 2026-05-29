package l2tp

import (
	"crypto/md5"
	"encoding/binary"
	"net"
	"testing"
)

// --- PPP Frame Tests ---

func TestParsePPPFrame_Standard(t *testing.T) {
	// Standard PPP frame: Address(0xFF) + Control(0x03) + Protocol(2) + Payload.
	frame := []byte{0xFF, 0x03, 0xC0, 0x21, 0x01, 0x02, 0x03}
	ppp, err := ParsePPPFrame(frame)
	if err != nil {
		t.Fatalf("ParsePPPFrame failed: %v", err)
	}
	if ppp.Protocol != PPPProtoLCP {
		t.Errorf("Protocol: got 0x%04X, want 0x%04X", ppp.Protocol, PPPProtoLCP)
	}
	if len(ppp.Payload) != 3 {
		t.Errorf("Payload length: got %d, want 3", len(ppp.Payload))
	}
}

func TestParsePPPFrame_ACFC(t *testing.T) {
	// ACFC: no Address/Control, just Protocol(2) + Payload.
	frame := []byte{0xC0, 0x21, 0xAA, 0xBB}
	ppp, err := ParsePPPFrame(frame)
	if err != nil {
		t.Fatalf("ParsePPPFrame ACFC failed: %v", err)
	}
	if ppp.Protocol != PPPProtoLCP {
		t.Errorf("Protocol: got 0x%04X, want 0x%04X", ppp.Protocol, PPPProtoLCP)
	}
	if len(ppp.Payload) != 2 {
		t.Errorf("Payload length: got %d, want 2", len(ppp.Payload))
	}
}

func TestParsePPPFrame_PFC(t *testing.T) {
	// PFC: single-byte protocol (bit 0 is 1). IPv4 = 0x21 compressed.
	frame := []byte{0xFF, 0x03, 0x21, 0xDE, 0xAD}
	ppp, err := ParsePPPFrame(frame)
	if err != nil {
		t.Fatalf("ParsePPPFrame PFC failed: %v", err)
	}
	if ppp.Protocol != 0x21 {
		t.Errorf("Protocol: got 0x%04X, want 0x0021", ppp.Protocol)
	}
	if len(ppp.Payload) != 2 {
		t.Errorf("Payload length: got %d, want 2", len(ppp.Payload))
	}
}

func TestParsePPPFrame_TooShort(t *testing.T) {
	_, err := ParsePPPFrame([]byte{0xFF})
	if err == nil {
		t.Error("expected error for too-short frame")
	}
}

func TestSerializePPPFrame(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	frame := SerializePPPFrame(PPPProtoCHAP, payload)

	if frame[0] != 0xFF || frame[1] != 0x03 {
		t.Error("missing Address/Control fields")
	}
	proto := binary.BigEndian.Uint16(frame[2:4])
	if proto != PPPProtoCHAP {
		t.Errorf("Protocol: got 0x%04X, want 0x%04X", proto, PPPProtoCHAP)
	}
	if len(frame) != 4+3 {
		t.Errorf("Frame length: got %d, want 7", len(frame))
	}
}

func TestSerializePPPFrame_RoundTrip(t *testing.T) {
	payload := []byte{0xAA, 0xBB, 0xCC}
	frame := SerializePPPFrame(PPPProtoIPCP, payload)

	ppp, err := ParsePPPFrame(frame)
	if err != nil {
		t.Fatalf("round-trip failed: %v", err)
	}
	if ppp.Protocol != PPPProtoIPCP {
		t.Errorf("Protocol mismatch: got 0x%04X, want 0x%04X", ppp.Protocol, PPPProtoIPCP)
	}
	if len(ppp.Payload) != 3 {
		t.Errorf("Payload length: got %d, want 3", len(ppp.Payload))
	}
}

// --- LCP Tests ---

func TestLCPHandler_BuildConfigureRequest(t *testing.T) {
	h := NewLCPHandler()
	req := h.BuildConfigureRequest()

	if len(req) < 4 {
		t.Fatalf("Configure-Request too short: %d bytes", len(req))
	}
	if req[0] != LCPConfigureRequest {
		t.Errorf("Code: got %d, want %d", req[0], LCPConfigureRequest)
	}
	if h.State() != LCPStateReqSent {
		t.Errorf("State: got %d, want %d", h.State(), LCPStateReqSent)
	}
}

func TestLCPHandler_ConfigureAckRoundTrip(t *testing.T) {
	h := NewLCPHandler()
	req := h.BuildConfigureRequest()
	id := req[1]

	// Simulate peer sending Configure-Ack with our ID.
	ackPkt := make([]byte, 4)
	ackPkt[0] = LCPConfigureAck
	ackPkt[1] = id
	binary.BigEndian.PutUint16(ackPkt[2:4], 4)

	resp := h.Handle(ackPkt)
	if resp != nil {
		t.Error("Configure-Ack should not produce response")
	}

	if !h.ourConfigAcked {
		t.Error("ourConfigAcked should be true")
	}
}

func TestLCPHandler_PeerConfigureRequest_AcceptCHAP(t *testing.T) {
	h := NewLCPHandler()
	// Build peer request with: MRU=1400, AuthProto=CHAP(0xC223), MagicNumber.
	var opts []byte
	// MRU
	opts = append(opts, LCPOptMRU, 4, 0x05, 0x78) // 1400
	// Auth: CHAP MD5
	opts = append(opts, LCPOptAuthProto, 5, 0xC2, 0x23, 5)
	// Magic: 0x12345678
	opts = append(opts, LCPOptMagicNumber, 6, 0x12, 0x34, 0x56, 0x78)

	pktLen := uint16(4 + len(opts))
	pkt := make([]byte, pktLen)
	pkt[0] = LCPConfigureRequest
	pkt[1] = 1
	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	copy(pkt[4:], opts)

	resp := h.Handle(pkt)
	if resp == nil {
		t.Fatal("expected response to peer Configure-Request")
	}
	if resp[0] != LCPConfigureAck {
		t.Errorf("expected Configure-Ack, got code %d", resp[0])
	}
}

func TestLCPHandler_PeerConfigureRequest_NakPAP(t *testing.T) {
	h := NewLCPHandler()
	// Build peer request with PAP (0xC023) — should be Nak'd to CHAP.
	opts := []byte{LCPOptAuthProto, 4, 0xC0, 0x23} // PAP

	pktLen := uint16(4 + len(opts))
	pkt := make([]byte, pktLen)
	pkt[0] = LCPConfigureRequest
	pkt[1] = 1
	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	copy(pkt[4:], opts)

	resp := h.Handle(pkt)
	if resp == nil {
		t.Fatal("expected Nak response")
	}
	if resp[0] != LCPConfigureNak {
		t.Errorf("expected Configure-Nak, got code %d", resp[0])
	}
}

func TestLCPHandler_EchoRequest(t *testing.T) {
	h := NewLCPHandler()
	h.state = LCPStateOpened

	// Build Echo-Request with peer's magic.
	var payload []byte
	magic := make([]byte, 4)
	binary.BigEndian.PutUint32(magic, 0xDEADBEEF)
	payload = append(payload, magic...)

	pktLen := uint16(4 + len(payload))
	pkt := make([]byte, pktLen)
	pkt[0] = LCPEchoRequest
	pkt[1] = 42
	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	copy(pkt[4:], payload)

	resp := h.Handle(pkt)
	if resp == nil {
		t.Fatal("expected Echo-Reply")
	}
	if resp[0] != LCPEchoReply {
		t.Errorf("expected Echo-Reply, got code %d", resp[0])
	}
	if resp[1] != 42 {
		t.Errorf("Echo-Reply ID: got %d, want 42", resp[1])
	}
}

func TestLCPHandler_ProtocolReject(t *testing.T) {
	h := NewLCPHandler()
	rej := h.BuildProtocolReject(PPPProtoCCP, []byte{0x01, 0x02})
	if rej == nil {
		t.Fatal("expected Protocol-Reject")
	}
	if rej[0] != LCPProtocolReject {
		t.Errorf("expected Protocol-Reject code, got %d", rej[0])
	}
}

// --- CHAP Tests ---

type mockUserDB struct {
	users map[string]string
}

func (m *mockUserDB) LookupUser(username string) (string, bool) {
	pw, ok := m.users[username]
	return pw, ok
}

func TestCHAPHandler_SuccessfulAuth(t *testing.T) {
	db := &mockUserDB{users: map[string]string{"testuser": "testpass"}}
	h := NewCHAPHandler("server", db)

	// Step 1: Build challenge.
	challenge := h.BuildChallenge()
	if challenge[0] != CHAPChallenge {
		t.Errorf("expected Challenge code, got %d", challenge[0])
	}

	// Step 2: Simulate client response.
	// MD5(ID || password || challenge_value)
	id := h.challengeID
	hash := md5.New()
	hash.Write([]byte{id})
	hash.Write([]byte("testpass"))
	hash.Write(h.challenge)
	responseValue := hash.Sum(nil)

	username := []byte("testuser")
	// Response packet: Code(1) + ID(1) + Length(2) + ValueSize(1) + Value(16) + Name.
	totalLen := 4 + 1 + len(responseValue) + len(username)
	resp := make([]byte, totalLen)
	resp[0] = CHAPResponse
	resp[1] = id
	binary.BigEndian.PutUint16(resp[2:4], uint16(totalLen))
	resp[4] = byte(len(responseValue))
	copy(resp[5:5+len(responseValue)], responseValue)
	copy(resp[5+len(responseValue):], username)

	result := h.Handle(resp)
	if result == nil {
		t.Fatal("expected CHAP response")
	}
	if result[0] != CHAPSuccess {
		t.Errorf("expected Success, got code %d", result[0])
	}
	if !h.IsAuthenticated() {
		t.Error("expected IsAuthenticated=true")
	}
	if h.Username() != "testuser" {
		t.Errorf("Username: got %q, want %q", h.Username(), "testuser")
	}
}

func TestCHAPHandler_FailedAuth_WrongPassword(t *testing.T) {
	db := &mockUserDB{users: map[string]string{"testuser": "correctpass"}}
	h := NewCHAPHandler("server", db)

	h.BuildChallenge()
	id := h.challengeID

	// Use wrong password for MD5.
	hash := md5.New()
	hash.Write([]byte{id})
	hash.Write([]byte("wrongpass"))
	hash.Write(h.challenge)
	responseValue := hash.Sum(nil)

	username := []byte("testuser")
	totalLen := 4 + 1 + len(responseValue) + len(username)
	resp := make([]byte, totalLen)
	resp[0] = CHAPResponse
	resp[1] = id
	binary.BigEndian.PutUint16(resp[2:4], uint16(totalLen))
	resp[4] = byte(len(responseValue))
	copy(resp[5:5+len(responseValue)], responseValue)
	copy(resp[5+len(responseValue):], username)

	result := h.Handle(resp)
	if result == nil {
		t.Fatal("expected CHAP response")
	}
	if result[0] != CHAPFailure {
		t.Errorf("expected Failure, got code %d", result[0])
	}
	if h.IsAuthenticated() {
		t.Error("should not be authenticated")
	}
}

func TestCHAPHandler_FailedAuth_UnknownUser(t *testing.T) {
	db := &mockUserDB{users: map[string]string{}}
	h := NewCHAPHandler("server", db)

	h.BuildChallenge()
	id := h.challengeID

	hash := md5.New()
	hash.Write([]byte{id})
	hash.Write([]byte("anypass"))
	hash.Write(h.challenge)
	responseValue := hash.Sum(nil)

	username := []byte("nobody")
	totalLen := 4 + 1 + len(responseValue) + len(username)
	resp := make([]byte, totalLen)
	resp[0] = CHAPResponse
	resp[1] = id
	binary.BigEndian.PutUint16(resp[2:4], uint16(totalLen))
	resp[4] = byte(len(responseValue))
	copy(resp[5:5+len(responseValue)], responseValue)
	copy(resp[5+len(responseValue):], username)

	result := h.Handle(resp)
	if result[0] != CHAPFailure {
		t.Errorf("expected Failure for unknown user, got code %d", result[0])
	}
}

// --- IPCP Tests ---

func TestIPCPHandler_NakZeroIP(t *testing.T) {
	h := NewIPCPHandler(
		net.IPv4(192, 168, 42, 100),
		net.IPv4(192, 168, 42, 1),
		nil, nil,
	)

	// Client requests 0.0.0.0 → server should Nak with assigned IP.
	opts := []byte{IPCPOptIPAddress, 6, 0, 0, 0, 0}
	pktLen := uint16(4 + len(opts))
	pkt := make([]byte, pktLen)
	pkt[0] = IPCPConfigureRequest
	pkt[1] = 1
	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	copy(pkt[4:], opts)

	resp := h.Handle(pkt)
	if resp == nil {
		t.Fatal("expected IPCP response")
	}
	if resp[0] != IPCPConfigureNak {
		t.Errorf("expected Configure-Nak, got code %d", resp[0])
	}
	// Verify the Nak contains the assigned IP.
	if len(resp) >= 10 {
		nakIP := net.IP(resp[6:10])
		expected := net.IPv4(192, 168, 42, 100).To4()
		if !nakIP.Equal(expected) {
			t.Errorf("Nak IP: got %s, want %s", nakIP, expected)
		}
	}
}

func TestIPCPHandler_AckCorrectIP(t *testing.T) {
	assignedIP := net.IPv4(192, 168, 42, 100)
	h := NewIPCPHandler(
		assignedIP,
		net.IPv4(192, 168, 42, 1),
		nil, nil,
	)

	// Client requests the correct assigned IP.
	ip := assignedIP.To4()
	opts := []byte{IPCPOptIPAddress, 6, ip[0], ip[1], ip[2], ip[3]}
	pktLen := uint16(4 + len(opts))
	pkt := make([]byte, pktLen)
	pkt[0] = IPCPConfigureRequest
	pkt[1] = 1
	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	copy(pkt[4:], opts)

	resp := h.Handle(pkt)
	if resp == nil {
		t.Fatal("expected IPCP response")
	}
	if resp[0] != IPCPConfigureAck {
		t.Errorf("expected Configure-Ack, got code %d", resp[0])
	}
}

func TestIPCPHandler_DNSNak(t *testing.T) {
	h := NewIPCPHandler(
		net.IPv4(192, 168, 42, 100),
		net.IPv4(192, 168, 42, 1),
		net.IPv4(1, 1, 1, 1),
		net.IPv4(1, 0, 0, 1),
	)

	// Client requests DNS 0.0.0.0 → should Nak with configured DNS.
	opts := []byte{
		IPCPOptPrimaryDNS, 6, 0, 0, 0, 0,
		IPCPOptSecondaryDNS, 6, 0, 0, 0, 0,
	}
	pktLen := uint16(4 + len(opts))
	pkt := make([]byte, pktLen)
	pkt[0] = IPCPConfigureRequest
	pkt[1] = 1
	binary.BigEndian.PutUint16(pkt[2:4], pktLen)
	copy(pkt[4:], opts)

	resp := h.Handle(pkt)
	if resp == nil {
		t.Fatal("expected IPCP response")
	}
	if resp[0] != IPCPConfigureNak {
		t.Errorf("expected Configure-Nak for DNS, got code %d", resp[0])
	}
}

func TestIPCPHandler_BuildConfigureRequest(t *testing.T) {
	h := NewIPCPHandler(
		net.IPv4(192, 168, 42, 100),
		net.IPv4(192, 168, 42, 1),
		nil, nil,
	)

	req := h.BuildConfigureRequest()
	if len(req) < 4 {
		t.Fatalf("Configure-Request too short: %d bytes", len(req))
	}
	if req[0] != IPCPConfigureRequest {
		t.Errorf("Code: got %d, want %d", req[0], IPCPConfigureRequest)
	}
	// Verify gateway IP in the option.
	if len(req) >= 10 {
		gwIP := net.IP(req[6:10])
		expected := net.IPv4(192, 168, 42, 1).To4()
		if !gwIP.Equal(expected) {
			t.Errorf("Gateway IP: got %s, want %s", gwIP, expected)
		}
	}
}
