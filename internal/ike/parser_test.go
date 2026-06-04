package ike

import (
	"encoding/binary"
	"testing"
)

func TestParseV2_UnknownNonCriticalPayload(t *testing.T) {
	// Construct a minimal IKEv2 payload chain with an unknown payload type (200).
	// Non-critical (Critical bit = 0) → should be parsed as RawPayload, chain continues.
	unknownType := PayloadType(200)
	payloadBody := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	payloadLen := uint16(PayloadHeaderLen + len(payloadBody))

	buf := make([]byte, payloadLen)
	buf[0] = byte(PayloadNone)  // NextPayload = None (end of chain)
	buf[1] = 0x00               // Critical = 0
	binary.BigEndian.PutUint16(buf[2:4], payloadLen)
	copy(buf[PayloadHeaderLen:], payloadBody)

	chain, err := ParsePayloadChain(buf, unknownType, true)
	if err != nil {
		t.Fatalf("non-critical unknown payload should not error: %v", err)
	}

	if len(chain) != 1 {
		t.Fatalf("expected 1 payload in chain, got %d", len(chain))
	}

	raw, ok := chain[0].Payload.(*RawPayload)
	if !ok {
		t.Fatalf("expected RawPayload, got %T", chain[0].Payload)
	}

	if raw.PayloadType != unknownType {
		t.Errorf("expected payload type %d, got %d", unknownType, raw.PayloadType)
	}

	if len(raw.Data) != len(payloadBody) {
		t.Errorf("expected %d bytes of data, got %d", len(payloadBody), len(raw.Data))
	}
}

func TestParseV2_UnknownCriticalPayload(t *testing.T) {
	// Construct a payload chain with an unknown payload type (200) and Critical bit set.
	// Per RFC 7296 §2.5, this MUST be rejected.
	unknownType := PayloadType(200)
	payloadBody := []byte{0xDE, 0xAD}
	payloadLen := uint16(PayloadHeaderLen + len(payloadBody))

	buf := make([]byte, payloadLen)
	buf[0] = byte(PayloadNone)  // NextPayload
	buf[1] = 0x80               // Critical bit SET
	binary.BigEndian.PutUint16(buf[2:4], payloadLen)
	copy(buf[PayloadHeaderLen:], payloadBody)

	_, err := ParsePayloadChain(buf, unknownType, true)
	if err == nil {
		t.Fatal("critical unknown payload should return error")
	}
}

func TestParseV1_UnknownPayloadGraceful(t *testing.T) {
	// IKEv1 with unknown payload type (100).
	unknownType := PayloadType(100)
	payloadBody := []byte{0x01, 0x02, 0x03}
	payloadLen := uint16(PayloadHeaderLen + len(payloadBody))

	buf := make([]byte, payloadLen)
	buf[0] = byte(PayloadNone)
	buf[1] = 0x00 // Non-critical
	binary.BigEndian.PutUint16(buf[2:4], payloadLen)
	copy(buf[PayloadHeaderLen:], payloadBody)

	chain, err := ParsePayloadChain(buf, unknownType, false)
	if err != nil {
		t.Fatalf("non-critical unknown v1 payload should not error: %v", err)
	}

	if len(chain) != 1 {
		t.Fatalf("expected 1 payload, got %d", len(chain))
	}

	_, ok := chain[0].Payload.(*RawPayload)
	if !ok {
		t.Fatalf("expected RawPayload, got %T", chain[0].Payload)
	}
}

func TestParseV2_KnownPayloadChainWithUnknown(t *testing.T) {
	// Build a chain: Nonce(40) → Unknown(250) → None
	// Both non-critical. Should parse both successfully.

	// Payload 1: Nonce
	nonceData := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	nonceLen := uint16(PayloadHeaderLen + len(nonceData))
	nonceBuf := make([]byte, nonceLen)
	nonceBuf[0] = byte(PayloadType(250)) // NextPayload = 250 (unknown)
	nonceBuf[1] = 0x00                   // Non-critical
	binary.BigEndian.PutUint16(nonceBuf[2:4], nonceLen)
	copy(nonceBuf[PayloadHeaderLen:], nonceData)

	// Payload 2: Unknown (250)
	unknownData := []byte{0x11, 0x22}
	unknownLen := uint16(PayloadHeaderLen + len(unknownData))
	unknownBuf := make([]byte, unknownLen)
	unknownBuf[0] = byte(PayloadNone) // NextPayload = None
	unknownBuf[1] = 0x00              // Non-critical
	binary.BigEndian.PutUint16(unknownBuf[2:4], unknownLen)
	copy(unknownBuf[PayloadHeaderLen:], unknownData)

	// Concatenate both payloads.
	buf := append(nonceBuf, unknownBuf...)

	chain, err := ParsePayloadChain(buf, PayloadNonce, true)
	if err != nil {
		t.Fatalf("mixed chain should parse: %v", err)
	}

	if len(chain) != 2 {
		t.Fatalf("expected 2 payloads, got %d", len(chain))
	}

	// First should be NoncePayload.
	_, ok := chain[0].Payload.(*NoncePayload)
	if !ok {
		t.Errorf("first payload should be NoncePayload, got %T", chain[0].Payload)
	}

	// Second should be RawPayload (unknown type 250).
	raw, ok := chain[1].Payload.(*RawPayload)
	if !ok {
		t.Errorf("second payload should be RawPayload, got %T", chain[1].Payload)
	}

	if raw.PayloadType != PayloadType(250) {
		t.Errorf("unknown payload type: expected 250, got %d", raw.PayloadType)
	}
}

func TestHeaderValidate_VersionAbove2(t *testing.T) {
	// Per our relaxed validation, version > 2 should warn but NOT error.
	hdr := Header{
		MajorVersion: 3,
		MinorVersion: 0,
		Length:        HeaderLen,
	}
	// Set a non-zero initiator SPI to avoid IKEv2-specific check issues.
	hdr.InitiatorSPI = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	err := hdr.Validate()
	if err != nil {
		t.Errorf("version 3 should not error (relaxed): %v", err)
	}
}

func TestHeaderValidate_Version0(t *testing.T) {
	// Version 0 is always invalid.
	hdr := Header{
		MajorVersion: 0,
		Length:        HeaderLen,
	}

	err := hdr.Validate()
	if err == nil {
		t.Error("version 0 should error")
	}
}
