package ike

import (
	"bytes"
	"testing"
)

func TestCryptoDH(t *testing.T) {
	dh, err := NewDHGroup(DHGroup14)
	if err != nil {
		t.Fatalf("Failed to init DH group 14: %v", err)
	}

	priv1, pub1, err := dh.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair 1: %v", err)
	}

	priv2, pub2, err := dh.GenerateKeypair()
	if err != nil {
		t.Fatalf("Failed to generate keypair 2: %v", err)
	}

	shared1, err := dh.ComputeSharedSecret(priv1, pub2)
	if err != nil {
		t.Fatalf("Failed to compute shared secret 1: %v", err)
	}

	shared2, err := dh.ComputeSharedSecret(priv2, pub1)
	if err != nil {
		t.Fatalf("Failed to compute shared secret 2: %v", err)
	}

	if !bytes.Equal(shared1, shared2) {
		t.Error("Shared secrets do not match")
	}
}

func TestCryptoPRF(t *testing.T) {
	prf, err := NewPRF(PRFHMAC_SHA256)
	if err != nil {
		t.Fatalf("Failed to init PRF: %v", err)
	}

	key := []byte("secret_key")
	data := []byte("hello_world")

	out := prf.Compute(key, data)
	if len(out) != prf.OutputSize() {
		t.Errorf("Expected PRF output size %d, got %d", prf.OutputSize(), len(out))
	}
}
