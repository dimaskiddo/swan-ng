package ike

import (
	"bytes"
	"testing"
)

func TestIKEHeader(t *testing.T) {
	// Create an IKEv1 header
	h1 := Header{
		InitiatorSPI: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		ResponderSPI: [8]byte{8, 7, 6, 5, 4, 3, 2, 1},
		NextPayload:  PayloadSAV1,
		ExchangeType: ExchangeIdentityProtect,
		Flags:        FlagV1Encryption,
		MessageID:    0,
		Length:       HeaderLen + 64,
	}
	h1.SetIKEv1()

	if h1.IsIKEv2() {
		t.Error("Expected IKEv1 header, got IKEv2")
	}

	buf := make([]byte, HeaderLen)
	if err := h1.Marshal(buf); err != nil {
		t.Fatalf("Failed to marshal IKEv1 header: %v", err)
	}

	parsed, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("Failed to parse IKEv1 header: %v", err)
	}

	if parsed.ExchangeType != ExchangeIdentityProtect {
		t.Errorf("Expected exchange type %v, got %v", ExchangeIdentityProtect, parsed.ExchangeType)
	}
	if parsed.NextPayload != PayloadSAV1 {
		t.Errorf("Expected next payload %v, got %v", PayloadSAV1, parsed.NextPayload)
	}
	if parsed.MajorVersion != 1 || parsed.MinorVersion != 0 {
		t.Errorf("Expected version 1.0, got %d.%d", parsed.MajorVersion, parsed.MinorVersion)
	}
	if !bytes.Equal(parsed.InitiatorSPI[:], h1.InitiatorSPI[:]) {
		t.Error("SPI mismatch")
	}
}
