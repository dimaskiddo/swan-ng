package ike

import (
	"bytes"
	"testing"
)

func TestPayloadChain(t *testing.T) {
	// Build a simple payload chain with ID and Nonce
	idPayload := &IDv1Payload{
		IDType: IDIPv4Addr,
		Data:   []byte{192, 168, 1, 1},
	}
	noncePayload := &NonceV1Payload{
		NonceData: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	}

	chain := []Payload{idPayload, noncePayload}

	marshaled, firstPayload, err := MarshalPayloadChain(chain)
	if err != nil {
		t.Fatalf("Failed to marshal payload chain: %v", err)
	}

	if firstPayload != PayloadIDV1 {
		t.Errorf("Expected first payload to be IDv1, got %v", firstPayload)
	}

	parsedChain, err := ParsePayloadChain(marshaled, firstPayload, false)
	if err != nil {
		t.Fatalf("Failed to parse payload chain: %v", err)
	}

	if len(parsedChain) != 2 {
		t.Fatalf("Expected 2 payloads in chain, got %d", len(parsedChain))
	}

	parsedID, ok := parsedChain[0].Payload.(*IDv1Payload)
	if !ok {
		t.Fatalf("Expected first payload to be IDv1Payload, got %T", parsedChain[0].Payload)
	}
	if parsedID.IDType != IDIPv4Addr {
		t.Errorf("Expected IDType %v, got %v", IDIPv4Addr, parsedID.IDType)
	}
	if !bytes.Equal(parsedID.Data, idPayload.Data) {
		t.Error("ID data mismatch")
	}

	parsedNonce, ok := parsedChain[1].Payload.(*NonceV1Payload)
	if !ok {
		t.Fatalf("Expected second payload to be NonceV1Payload, got %T", parsedChain[1].Payload)
	}
	if !bytes.Equal(parsedNonce.NonceData, noncePayload.NonceData) {
		t.Error("Nonce data mismatch")
	}
}
