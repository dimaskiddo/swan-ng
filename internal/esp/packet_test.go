package esp

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
)

func makeTestSAPair(t *testing.T, suite CipherSuite, keySize int) (*SecurityAssociation, *SecurityAssociation) {
	t.Helper()

	key := make([]byte, keySize)
	salt := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	spiOut := uint32(0xAAAA0001)
	spiIn := uint32(0xBBBB0001)

	saOut, err := NewTestSA(spiOut, suite, key, salt, &net.UDPAddr{
		IP:   net.IPv4(10, 0, 0, 2),
		Port: 4500,
	}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Inbound SA uses same key/salt but different SPI (in real IPsec,
	// each direction has its own SA; for testing we share crypto material).
	saIn, err := NewTestSA(spiOut, suite, key, salt, &net.UDPAddr{
		IP:   net.IPv4(10, 0, 0, 1),
		Port: 4500,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	_ = spiIn

	return saOut, saIn
}

func TestEncryptDecryptRoundtrip_AES128GCM(t *testing.T) {
	saOut, saIn := makeTestSAPair(t, AES128GCM, 16)

	payload := []byte{0x45, 0x00, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
		0x0A, 0x00, 0x00, 0x02, 0x04, 0xD2, 0x16, 0x2E,
		0x00, 0x08, 0x00, 0x00}

	espPacket, err := Encrypt(saOut, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, nextHdr, err := Decrypt(saIn, espPacket)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if nextHdr != NextHeaderIPv4 {
		t.Fatalf("expected NextHeader %d, got %d", NextHeaderIPv4, nextHdr)
	}

	if !bytes.Equal(payload, decrypted) {
		t.Fatal("decrypted payload does not match original")
	}
}

func TestEncryptDecryptRoundtrip_AES256GCM(t *testing.T) {
	saOut, saIn := makeTestSAPair(t, AES256GCM, 32)

	payload := make([]byte, 100)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	espPacket, err := Encrypt(saOut, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, nextHdr, err := Decrypt(saIn, espPacket)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if nextHdr != NextHeaderIPv4 {
		t.Fatalf("expected NextHeader %d, got %d", NextHeaderIPv4, nextHdr)
	}

	if !bytes.Equal(payload, decrypted) {
		t.Fatal("decrypted payload does not match original")
	}
}

func TestEncryptDecryptRoundtrip_ChaCha20(t *testing.T) {
	saOut, saIn := makeTestSAPair(t, CHACHA20POLY1305, 32)

	payload := []byte("Hello from ChaCha20-Poly1305 ESP tunnel!")

	espPacket, err := Encrypt(saOut, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, _, err := Decrypt(saIn, espPacket)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(payload, decrypted) {
		t.Fatal("decrypted payload does not match original")
	}
}

func TestParseHeader(t *testing.T) {
	buf := []byte{0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01}

	hdr, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader failed: %v", err)
	}

	if hdr.SPI != 0x12345678 {
		t.Fatalf("SPI mismatch: expected 0x12345678, got 0x%08X", hdr.SPI)
	}
	if hdr.SeqNum != 1 {
		t.Fatalf("SeqNum mismatch: expected 1, got %d", hdr.SeqNum)
	}
}

func TestParseHeader_TooShort(t *testing.T) {
	buf := []byte{0x12, 0x34, 0x56}

	_, err := ParseHeader(buf)
	if err == nil {
		t.Fatal("expected error for short buffer")
	}
}

func TestMarshalHeader(t *testing.T) {
	buf := make([]byte, 8)
	hdr := ESPHeader{SPI: 0xDEADBEEF, SeqNum: 42}

	MarshalHeader(buf, hdr)

	parsed, err := ParseHeader(buf)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SPI != hdr.SPI || parsed.SeqNum != hdr.SeqNum {
		t.Fatal("marshal/parse roundtrip mismatch")
	}
}

func TestEncryptDecrypt_DummyPacket(t *testing.T) {
	saOut, saIn := makeTestSAPair(t, AES128GCM, 16)

	// Dummy packets have NextHeader=59 per RFC 4303 §2.6.
	dummyPayload := make([]byte, 64)
	if _, err := rand.Read(dummyPayload); err != nil {
		t.Fatal(err)
	}

	espPacket, err := Encrypt(saOut, dummyPayload, NextHeaderDummy)
	if err != nil {
		t.Fatalf("Encrypt dummy failed: %v", err)
	}

	decrypted, nextHdr, err := Decrypt(saIn, espPacket)
	if err != nil {
		t.Fatalf("Decrypt dummy failed: %v", err)
	}

	if nextHdr != NextHeaderDummy {
		t.Fatalf("expected NextHeaderDummy (59), got %d", nextHdr)
	}

	// Dummy packets return nil payload per our implementation.
	if decrypted != nil {
		t.Fatal("dummy packet should return nil payload")
	}
}

func TestEncryptDecrypt_AntiReplay(t *testing.T) {
	saOut, saIn := makeTestSAPair(t, AES128GCM, 16)

	payload := []byte("anti-replay test payload data")

	espPacket1, err := Encrypt(saOut, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}

	// First decrypt should succeed.
	_, _, err = Decrypt(saIn, espPacket1)
	if err != nil {
		t.Fatalf("first decrypt should succeed: %v", err)
	}

	// Replaying the same packet should fail anti-replay.
	_, _, err = Decrypt(saIn, espPacket1)
	if err == nil {
		t.Fatal("replayed packet should be rejected")
	}
}

func TestEncryptDecrypt_MultiplePackets(t *testing.T) {
	saOut, saIn := makeTestSAPair(t, AES256GCM, 32)

	for i := 0; i < 100; i++ {
		payload := make([]byte, 20+i)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}

		espPacket, err := Encrypt(saOut, payload, NextHeaderIPv4)
		if err != nil {
			t.Fatalf("Encrypt %d failed: %v", i, err)
		}

		decrypted, _, err := Decrypt(saIn, espPacket)
		if err != nil {
			t.Fatalf("Decrypt %d failed: %v", i, err)
		}

		if !bytes.Equal(payload, decrypted) {
			t.Fatalf("payload mismatch at packet %d", i)
		}
	}
}

func TestDecrypt_TamperedPacket(t *testing.T) {
	saOut, saIn := makeTestSAPair(t, AES128GCM, 16)

	payload := []byte("tamper-proof test data")

	espPacket, err := Encrypt(saOut, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext.
	espPacket[len(espPacket)-5] ^= 0xFF

	_, _, err = Decrypt(saIn, espPacket)
	if err == nil {
		t.Fatal("tampered packet should fail AEAD authentication")
	}
}

func TestDecrypt_PacketTooShort(t *testing.T) {
	saIn := newTestSAHelper(t, 0x11111111)

	_, _, err := Decrypt(saIn, []byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for too-short packet")
	}
}

func TestEncrypt_NilSA(t *testing.T) {
	_, err := Encrypt(nil, []byte("data"), NextHeaderIPv4)
	if err == nil {
		t.Fatal("expected error for nil SA")
	}
}

func TestDecrypt_NilSA(t *testing.T) {
	_, _, err := Decrypt(nil, []byte{0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatal("expected error for nil SA")
	}
}

func TestBuildESPTrailer_Alignment(t *testing.T) {
	tests := []struct {
		payloadLen int
		wantPadLen int
	}{
		{0, 2},   // 0 + 0 + 2 = 2, need 2 pad to reach 4
		{1, 1},   // 1 + 1 + 2 = 4
		{2, 0},   // 2 + 0 + 2 = 4
		{3, 3},   // 3 + 3 + 2 = 8
		{4, 2},   // 4 + 2 + 2 = 8
		{5, 1},   // 5 + 1 + 2 = 8
		{6, 0},   // 6 + 0 + 2 = 8
		{10, 0},  // 10 + 0 + 2 = 12
		{11, 3},  // 11 + 3 + 2 = 16
	}

	for _, tc := range tests {
		payload := make([]byte, tc.payloadLen)
		result := buildESPTrailer(payload, NextHeaderIPv4)

		totalLen := len(result)
		if totalLen%4 != 0 {
			t.Errorf("payloadLen=%d: result len %d not 4-byte aligned", tc.payloadLen, totalLen)
		}

		// Check PadLength field.
		padLenField := int(result[len(result)-2])
		if padLenField != tc.wantPadLen {
			t.Errorf("payloadLen=%d: padLen=%d, want %d", tc.payloadLen, padLenField, tc.wantPadLen)
		}

		// Check NextHeader field.
		if result[len(result)-1] != NextHeaderIPv4 {
			t.Errorf("payloadLen=%d: nextHeader=%d, want %d", tc.payloadLen, result[len(result)-1], NextHeaderIPv4)
		}

		// Check padding content: 1, 2, 3, ...
		padStart := tc.payloadLen
		for i := 0; i < tc.wantPadLen; i++ {
			if result[padStart+i] != byte(i+1) {
				t.Errorf("payloadLen=%d: padding[%d]=%d, want %d",
					tc.payloadLen, i, result[padStart+i], i+1)
			}
		}
	}
}
