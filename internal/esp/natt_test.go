package esp

import (
	"bytes"
	"testing"
)

func TestClassifyNATT_ESPPacket(t *testing.T) {
	// SPI = 0x12345678 (non-zero first 4 bytes) → ESP.
	buf := []byte{0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01, 0xFF}

	pktType, payload, err := ClassifyNATT(buf)
	if err != nil {
		t.Fatalf("ClassifyNATT failed: %v", err)
	}

	if pktType != PacketTypeESP {
		t.Fatalf("expected PacketTypeESP, got %d", pktType)
	}

	// ESP packets are returned as-is (SPI is part of the ESP header).
	if !bytes.Equal(payload, buf) {
		t.Fatal("ESP payload should be the full buffer")
	}
}

func TestClassifyNATT_IKEPacket(t *testing.T) {
	// Non-ESP Marker: 4 zero bytes → IKE.
	ikeData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	buf := append([]byte{0x00, 0x00, 0x00, 0x00}, ikeData...)

	pktType, payload, err := ClassifyNATT(buf)
	if err != nil {
		t.Fatalf("ClassifyNATT failed: %v", err)
	}

	if pktType != PacketTypeIKE {
		t.Fatalf("expected PacketTypeIKE, got %d", pktType)
	}

	if !bytes.Equal(payload, ikeData) {
		t.Fatal("IKE payload should have Non-ESP Marker stripped")
	}
}

func TestClassifyNATT_TooShort(t *testing.T) {
	buf := []byte{0x12, 0x34}

	_, _, err := ClassifyNATT(buf)
	if err == nil {
		t.Fatal("expected error for too-short packet")
	}
}

func TestClassifyNATT_ESPTooShort(t *testing.T) {
	// Non-zero first 4 bytes but not enough for ESP header.
	buf := []byte{0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01}

	// 8 bytes is exactly ESPHeaderLen (SPI + SeqNum), but MinNATTESPPacketLen = 9.
	_, _, err := ClassifyNATT(buf)
	if err == nil {
		t.Fatal("expected error for ESP packet too short (no ciphertext)")
	}
}

func TestClassifyNATT_IKEEmptyPayload(t *testing.T) {
	// Non-ESP Marker with no IKE payload.
	buf := []byte{0x00, 0x00, 0x00, 0x00}

	pktType, payload, err := ClassifyNATT(buf)
	if err != nil {
		t.Fatalf("ClassifyNATT failed: %v", err)
	}

	if pktType != PacketTypeIKE {
		t.Fatalf("expected PacketTypeIKE, got %d", pktType)
	}

	if len(payload) != 0 {
		t.Fatalf("expected empty IKE payload, got %d bytes", len(payload))
	}
}

func TestPrependNonESPMarker(t *testing.T) {
	ikePacket := []byte{0xAA, 0xBB, 0xCC}

	result := PrependNonESPMarker(ikePacket)

	if len(result) != NonESPMarkerLen+len(ikePacket) {
		t.Fatalf("expected length %d, got %d", NonESPMarkerLen+len(ikePacket), len(result))
	}

	// First 4 bytes should be zeros.
	for i := 0; i < NonESPMarkerLen; i++ {
		if result[i] != 0 {
			t.Fatalf("Non-ESP Marker byte %d should be 0, got %d", i, result[i])
		}
	}

	// Rest should be original IKE packet.
	if !bytes.Equal(result[NonESPMarkerLen:], ikePacket) {
		t.Fatal("IKE payload mismatch after prepending marker")
	}
}

func TestNATTRoundtrip(t *testing.T) {
	// IKE → prepend marker → classify → should get IKE + original data.
	original := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	withMarker := PrependNonESPMarker(original)

	pktType, payload, err := ClassifyNATT(withMarker)
	if err != nil {
		t.Fatal(err)
	}

	if pktType != PacketTypeIKE {
		t.Fatal("expected IKE after roundtrip")
	}

	if !bytes.Equal(payload, original) {
		t.Fatal("payload mismatch after roundtrip")
	}
}
