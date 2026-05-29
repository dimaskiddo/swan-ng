package esp

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestNewAEAD_AES128GCM(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewAEAD(AES128GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD AES128GCM failed: %v", err)
	}

	if aead.NonceSize() != 12 {
		t.Fatalf("expected nonce size 12, got %d", aead.NonceSize())
	}

	if aead.Overhead() != 16 {
		t.Fatalf("expected overhead 16 (GCM tag), got %d", aead.Overhead())
	}
}

func TestNewAEAD_AES256GCM(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewAEAD(AES256GCM, key)
	if err != nil {
		t.Fatalf("NewAEAD AES256GCM failed: %v", err)
	}

	if aead.NonceSize() != 12 {
		t.Fatalf("expected nonce size 12, got %d", aead.NonceSize())
	}
}

func TestNewAEAD_ChaCha20(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	aead, err := NewAEAD(CHACHA20POLY1305, key)
	if err != nil {
		t.Fatalf("NewAEAD ChaCha20 failed: %v", err)
	}

	if aead.NonceSize() != 12 {
		t.Fatalf("expected nonce size 12, got %d", aead.NonceSize())
	}

	if aead.Overhead() != 16 {
		t.Fatalf("expected overhead 16 (Poly1305 tag), got %d", aead.Overhead())
	}
}

func TestNewAEAD_InvalidKeySize(t *testing.T) {
	key := make([]byte, 10)

	_, err := NewAEAD(AES128GCM, key)
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
}

func TestNewAEAD_UnsupportedSuite(t *testing.T) {
	key := make([]byte, 16)

	_, err := NewAEAD(CipherSuite(99), key)
	if err == nil {
		t.Fatal("expected error for unsupported cipher suite")
	}
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	suites := []struct {
		name    string
		suite   CipherSuite
		keySize int
	}{
		{"AES-128-GCM", AES128GCM, 16},
		{"AES-256-GCM", AES256GCM, 32},
		{"ChaCha20-Poly1305", CHACHA20POLY1305, 32},
	}

	for _, tc := range suites {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			if _, err := rand.Read(key); err != nil {
				t.Fatal(err)
			}

			salt := make([]byte, 4)
			if _, err := rand.Read(salt); err != nil {
				t.Fatal(err)
			}

			aead, err := NewAEAD(tc.suite, key)
			if err != nil {
				t.Fatalf("NewAEAD failed: %v", err)
			}

			plaintext := []byte("Hello, ESP packet payload data for testing!")
			seqNum := uint64(42)
			iv := SequenceToIV(seqNum)

			nonce, err := BuildNonce(salt, iv)
			if err != nil {
				t.Fatalf("BuildNonce failed: %v", err)
			}

			additionalData := []byte{0, 0, 0, 1, 0, 0, 0, 42} // SPI=1, SeqNum=42

			ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)

			decrypted, err := aead.Open(nil, nonce, ciphertext, additionalData)
			if err != nil {
				t.Fatalf("AEAD Open failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Fatal("decrypted plaintext does not match original")
			}
		})
	}
}

func TestBuildNonce(t *testing.T) {
	salt := []byte{0x01, 0x02, 0x03, 0x04}
	iv := []byte{0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	nonce, err := BuildNonce(salt, iv)
	if err != nil {
		t.Fatalf("BuildNonce failed: %v", err)
	}

	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}
	if !bytes.Equal(nonce, expected) {
		t.Fatalf("nonce mismatch: expected %x, got %x", expected, nonce)
	}
}

func TestBuildNonce_InvalidSaltSize(t *testing.T) {
	_, err := BuildNonce([]byte{1, 2, 3}, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if err == nil {
		t.Fatal("expected error for invalid salt size")
	}
}

func TestBuildNonce_InvalidIVSize(t *testing.T) {
	_, err := BuildNonce([]byte{1, 2, 3, 4}, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for invalid IV size")
	}
}

func TestSequenceToIV(t *testing.T) {
	iv := SequenceToIV(0x0102030405060708)
	expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	if !bytes.Equal(iv, expected) {
		t.Fatalf("IV mismatch: expected %x, got %x", expected, iv)
	}
}

func TestSequenceToIV_One(t *testing.T) {
	iv := SequenceToIV(1)
	expected := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

	if !bytes.Equal(iv, expected) {
		t.Fatalf("IV mismatch: expected %x, got %x", expected, iv)
	}
}

func TestCipherSuiteString(t *testing.T) {
	tests := []struct {
		suite    CipherSuite
		expected string
	}{
		{AES128GCM, "AES-128-GCM"},
		{AES256GCM, "AES-256-GCM"},
		{CHACHA20POLY1305, "CHACHA20-POLY1305"},
		{CipherSuite(99), "unknown(99)"},
	}

	for _, tc := range tests {
		if tc.suite.String() != tc.expected {
			t.Errorf("CipherSuite(%d).String() = %q, want %q", tc.suite, tc.suite.String(), tc.expected)
		}
	}
}
