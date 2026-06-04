package ike

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEAPPacketParseMarshalRoundTrip(t *testing.T) {
	// Build an EAP-Identity Request.
	original := &EAPPacket{
		Code:       EAPCodeRequest,
		Identifier: 42,
		Type:       EAPTypeIdentity,
		Data:       []byte("Please identify yourself"),
	}

	marshaled := original.Marshal()

	parsed, err := ParseEAPPacket(marshaled)
	if err != nil {
		t.Fatalf("ParseEAPPacket: %v", err)
	}

	if parsed.Code != original.Code {
		t.Errorf("Code: got %d, want %d", parsed.Code, original.Code)
	}
	if parsed.Identifier != original.Identifier {
		t.Errorf("Identifier: got %d, want %d", parsed.Identifier, original.Identifier)
	}
	if parsed.Type != original.Type {
		t.Errorf("Type: got %d, want %d", parsed.Type, original.Type)
	}
	if !bytes.Equal(parsed.Data, original.Data) {
		t.Errorf("Data mismatch")
	}
}

func TestEAPSuccessFailureMarshal(t *testing.T) {
	// EAP-Success: Code(1) + ID(1) + Length(2) = 4 bytes, no Type.
	success := BuildEAPSuccess(7)
	if len(success) != 4 {
		t.Fatalf("EAP-Success length: got %d, want 4", len(success))
	}
	if success[0] != EAPCodeSuccess {
		t.Errorf("EAP-Success code: got %d", success[0])
	}
	if success[1] != 7 {
		t.Errorf("EAP-Success ID: got %d", success[1])
	}
	parsedLen := binary.BigEndian.Uint16(success[2:4])
	if parsedLen != 4 {
		t.Errorf("EAP-Success encoded length: got %d", parsedLen)
	}

	// Round trip.
	pkt, err := ParseEAPPacket(success)
	if err != nil {
		t.Fatalf("ParseEAPPacket success: %v", err)
	}
	if pkt.Code != EAPCodeSuccess {
		t.Errorf("Parsed code: got %d", pkt.Code)
	}

	// EAP-Failure.
	failure := BuildEAPFailure(9)
	if failure[0] != EAPCodeFailure {
		t.Errorf("EAP-Failure code: got %d", failure[0])
	}
}

func TestEAPIdentityRequest(t *testing.T) {
	req := BuildEAPIdentityRequest(1)

	pkt, err := ParseEAPPacket(req)
	if err != nil {
		t.Fatalf("ParseEAPPacket: %v", err)
	}

	if pkt.Code != EAPCodeRequest {
		t.Errorf("Code: got %d, want %d", pkt.Code, EAPCodeRequest)
	}
	if pkt.Type != EAPTypeIdentity {
		t.Errorf("Type: got %d, want %d", pkt.Type, EAPTypeIdentity)
	}
}

func TestEAPIdentityResponse(t *testing.T) {
	// Build an EAP-Identity response.
	identity := "testuser@example.com"
	pkt := &EAPPacket{
		Code:       EAPCodeResponse,
		Identifier: 1,
		Type:       EAPTypeIdentity,
		Data:       []byte(identity),
	}

	data := pkt.Marshal()
	parsed, err := ParseEAPPacket(data)
	if err != nil {
		t.Fatalf("ParseEAPPacket: %v", err)
	}

	gotID, err := ParseEAPIdentityResponse(parsed)
	if err != nil {
		t.Fatalf("ParseEAPIdentityResponse: %v", err)
	}

	if gotID != identity {
		t.Errorf("Identity: got %q, want %q", gotID, identity)
	}
}

// TestMSCHAPv2NtPasswordHash verifies against RFC 2759 §9.3 test vectors.
// User: "User"  Password: "clientPass"
// Expected NtPasswordHash: 44EBBA8D5312B8D611474411F56989AE
func TestMSCHAPv2NtPasswordHash(t *testing.T) {
	hash := NtPasswordHash("clientPass")

	expected := []byte{
		0x44, 0xEB, 0xBA, 0x8D, 0x53, 0x12, 0xB8, 0xD6,
		0x11, 0x47, 0x44, 0x11, 0xF5, 0x69, 0x89, 0xAE,
	}

	if !bytes.Equal(hash, expected) {
		t.Errorf("NtPasswordHash mismatch:\n  got  %x\n  want %x", hash, expected)
	}
}

// TestMSCHAPv2HashNtPasswordHash verifies MD4(NtPasswordHash).
// Expected: 41C00C584BD2D91C4017A2A12FA59F3F
func TestMSCHAPv2HashNtPasswordHash(t *testing.T) {
	ntHash := NtPasswordHash("clientPass")
	hashHash := HashNtPasswordHash(ntHash)

	expected := []byte{
		0x41, 0xC0, 0x0C, 0x58, 0x4B, 0xD2, 0xD9, 0x1C,
		0x40, 0x17, 0xA2, 0xA1, 0x2F, 0xA5, 0x9F, 0x3F,
	}

	if !bytes.Equal(hashHash, expected) {
		t.Errorf("HashNtPasswordHash mismatch:\n  got  %x\n  want %x", hashHash, expected)
	}
}

// TestMSCHAPv2ChallengeHash verifies the ChallengeHash function.
// RFC 2759 §9.3 test vectors:
//
//	AuthenticatorChallenge: 5B5D7C7D7B3F2F3E3C2C602132262628
//	PeerChallenge: 21402324255E262A28295F2B3A337C7E
//	UserName: "User"
//	Expected ChallengeHash: D02E4386BCE91226
func TestMSCHAPv2ChallengeHash(t *testing.T) {
	authChallenge := []byte{
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
	}
	peerChallenge := []byte{
		0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
		0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E,
	}

	hash := ChallengeHash(peerChallenge, authChallenge, "User")

	expected := []byte{0xD0, 0x2E, 0x43, 0x86, 0xBC, 0xE9, 0x12, 0x26}

	if !bytes.Equal(hash, expected) {
		t.Errorf("ChallengeHash mismatch:\n  got  %x\n  want %x", hash, expected)
	}
}

// TestMSCHAPv2GenerateNTResponse verifies the complete NT-Response computation.
// RFC 2759 §9.3 test vectors:
//
//	Expected NT-Response: 82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF
func TestMSCHAPv2GenerateNTResponse(t *testing.T) {
	authChallenge := []byte{
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
	}
	peerChallenge := []byte{
		0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
		0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E,
	}

	ntResp, err := GenerateNTResponse(authChallenge, peerChallenge, "User", "clientPass")
	if err != nil {
		t.Fatalf("GenerateNTResponse: %v", err)
	}

	expected := []byte{
		0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E,
		0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54,
		0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF,
	}

	if !bytes.Equal(ntResp, expected) {
		t.Errorf("GenerateNTResponse mismatch:\n  got  %x\n  want %x", ntResp, expected)
	}
}

// TestMSCHAPv2AuthenticatorResponse verifies the authenticator response.
// RFC 2759 §9.3 test vectors:
//
//	Expected: "S=407A5589115FD0D6209F510FE9C04566932CDA56"
func TestMSCHAPv2AuthenticatorResponse(t *testing.T) {
	authChallenge := []byte{
		0x5B, 0x5D, 0x7C, 0x7D, 0x7B, 0x3F, 0x2F, 0x3E,
		0x3C, 0x2C, 0x60, 0x21, 0x32, 0x26, 0x26, 0x28,
	}
	peerChallenge := []byte{
		0x21, 0x40, 0x23, 0x24, 0x25, 0x5E, 0x26, 0x2A,
		0x28, 0x29, 0x5F, 0x2B, 0x3A, 0x33, 0x7C, 0x7E,
	}
	ntResponse := []byte{
		0x82, 0x30, 0x9E, 0xCD, 0x8D, 0x70, 0x8B, 0x5E,
		0xA0, 0x8F, 0xAA, 0x39, 0x81, 0xCD, 0x83, 0x54,
		0x42, 0x33, 0x11, 0x4A, 0x3D, 0x85, 0xD6, 0xDF,
	}

	authResp := GenerateAuthenticatorResponse("clientPass", ntResponse,
		peerChallenge, authChallenge, "User")

	expected := "S=407A5589115FD0D6209F510FE9C04566932CDA56"

	if authResp != expected {
		t.Errorf("AuthenticatorResponse:\n  got  %s\n  want %s", authResp, expected)
	}
}

// TestMSCHAPv2FullExchange simulates a complete MSCHAPv2 challenge-response flow.
func TestMSCHAPv2FullExchange(t *testing.T) {
	username := "testuser"
	password := "testpass123"

	// Server generates challenge.
	serverChallenge, err := GenerateMSCHAPv2Challenge()
	if err != nil {
		t.Fatalf("GenerateMSCHAPv2Challenge: %v", err)
	}

	if len(serverChallenge) != 16 {
		t.Fatalf("Challenge length: got %d, want 16", len(serverChallenge))
	}

	// Build challenge packet.
	challengePkt := BuildMSCHAPv2Challenge(1, 1, serverChallenge, "swan-ng")
	pkt, err := ParseEAPPacket(challengePkt)
	if err != nil {
		t.Fatalf("Parse challenge: %v", err)
	}
	if pkt.Type != EAPTypeMSCHAPv2 {
		t.Fatalf("Challenge EAP type: got %d, want %d", pkt.Type, EAPTypeMSCHAPv2)
	}

	// Client generates response.
	peerChallenge := make([]byte, 16)
	for i := range peerChallenge {
		peerChallenge[i] = byte(i + 1)
	}

	ntResp, err := GenerateNTResponse(serverChallenge, peerChallenge, username, password)
	if err != nil {
		t.Fatalf("GenerateNTResponse: %v", err)
	}

	// Build MSCHAPv2 Response (49 bytes): PeerChallenge(16) + Reserved(8) + NTResponse(24) + Flags(1)
	responseValue := make([]byte, 49)
	copy(responseValue[0:16], peerChallenge)
	// reserved bytes 16-23 are zero
	copy(responseValue[24:48], ntResp)
	// flags byte 48 is zero

	// Build MSCHAPv2 response packet data.
	nameBytes := []byte(username)
	msLen := uint16(5 + 49 + len(nameBytes))
	mschapResp := make([]byte, msLen)
	mschapResp[0] = MSCHAPv2OpResponse
	mschapResp[1] = 1 // MS-CHAPv2-ID
	binary.BigEndian.PutUint16(mschapResp[2:4], msLen)
	mschapResp[4] = 49 // Value-Size
	copy(mschapResp[5:], responseValue)
	copy(mschapResp[5+49:], nameBytes)

	// Server verifies.
	authResp, ok := VerifyMSCHAPv2Response(mschapResp, serverChallenge, username, password)
	if !ok {
		t.Fatal("VerifyMSCHAPv2Response failed")
	}

	if len(authResp) < 3 || authResp[:2] != "S=" {
		t.Errorf("AuthResp should start with 'S=', got %q", authResp)
	}

	// Test MSK derivation.
	msk := GetMSCHAPv2MSK(password, ntResp)
	if len(msk) != 64 {
		t.Errorf("MSK length: got %d, want 64", len(msk))
	}

	// MSK should not be all zeros.
	allZero := true
	for _, b := range msk {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("MSK is all zeros")
	}
}

// TestMSCHAPv2VerifyBadPassword ensures wrong password fails verification.
func TestMSCHAPv2VerifyBadPassword(t *testing.T) {
	username := "testuser"
	correctPassword := "correct"
	wrongPassword := "wrong"

	serverChallenge := make([]byte, 16)
	for i := range serverChallenge {
		serverChallenge[i] = byte(i + 0xAA)
	}

	peerChallenge := make([]byte, 16)
	for i := range peerChallenge {
		peerChallenge[i] = byte(i + 0xBB)
	}

	// Generate response with correct password.
	ntResp, err := GenerateNTResponse(serverChallenge, peerChallenge, username, correctPassword)
	if err != nil {
		t.Fatalf("GenerateNTResponse: %v", err)
	}

	responseValue := make([]byte, 49)
	copy(responseValue[0:16], peerChallenge)
	copy(responseValue[24:48], ntResp)

	msLen := uint16(5 + 49)
	mschapResp := make([]byte, msLen)
	mschapResp[0] = MSCHAPv2OpResponse
	mschapResp[1] = 1
	binary.BigEndian.PutUint16(mschapResp[2:4], msLen)
	mschapResp[4] = 49
	copy(mschapResp[5:], responseValue)

	// Verify with wrong password — should fail.
	_, ok := VerifyMSCHAPv2Response(mschapResp, serverChallenge, username, wrongPassword)
	if ok {
		t.Error("VerifyMSCHAPv2Response should fail with wrong password")
	}

	// Verify with correct password — should succeed.
	_, ok = VerifyMSCHAPv2Response(mschapResp, serverChallenge, username, correctPassword)
	if !ok {
		t.Error("VerifyMSCHAPv2Response should succeed with correct password")
	}
}
