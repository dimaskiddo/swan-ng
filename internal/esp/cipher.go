package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// CipherSuite identifies the AEAD algorithm for an ESP Security Association.
type CipherSuite uint8

const (
	// AES128GCM uses AES-128-GCM (RFC 4106). Key: 20 bytes (16 key + 4 salt).
	AES128GCM CipherSuite = iota + 1

	// AES256GCM uses AES-256-GCM (RFC 4106). Key: 36 bytes (32 key + 4 salt).
	AES256GCM

	// CHACHA20POLY1305 uses ChaCha20-Poly1305 (RFC 7634). Key: 36 bytes (32 key + 4 salt).
	CHACHA20POLY1305
)

// String returns a human-readable cipher suite name.
func (cs CipherSuite) String() string {
	switch cs {
	case AES128GCM:
		return "AES-128-GCM"

	case AES256GCM:
		return "AES-256-GCM"

	case CHACHA20POLY1305:
		return "CHACHA20-POLY1305"

	default:
		return fmt.Sprintf("unknown(%d)", cs)
	}
}

// AEADKeySize returns the raw encryption key size (without salt) for a cipher suite.
func AEADKeySize(suite CipherSuite) int {
	switch suite {
	case AES128GCM:
		return 16

	case AES256GCM:
		return 32

	case CHACHA20POLY1305:
		return 32

	default:
		return 0
	}
}

// AEADSaltSize returns the salt size in bytes. Per RFC 4106 / RFC 7634,
// all three suites use a 4-byte salt prepended to the 8-byte IV to form
// a 12-byte nonce.
func AEADSaltSize(suite CipherSuite) int {
	return 4
}

// AEADIVSize returns the explicit IV size transmitted in each ESP packet.
// Per RFC 4106 §3.1 and RFC 7634 §3: 8 bytes.
func AEADIVSize(suite CipherSuite) int {
	return 8
}

// AEADNonceSize returns the full nonce size for the AEAD cipher.
// All three suites use 12-byte nonces: 4-byte salt + 8-byte IV.
func AEADNonceSize(suite CipherSuite) int {
	return 12
}

// AEADOverhead returns the total per-packet overhead added by the AEAD
// cipher: explicit IV (8) + authentication tag size.
func AEADOverhead(suite CipherSuite, aead cipher.AEAD) int {
	return AEADIVSize(suite) + aead.Overhead()
}

// NewAEAD creates an AEAD cipher instance for the given suite.
// key must contain exactly AEADKeySize(suite) bytes of encryption key material.
// The 4-byte salt is NOT included in key — it's passed separately via BuildNonce.
func NewAEAD(suite CipherSuite, key []byte) (cipher.AEAD, error) {
	expectedKeySize := AEADKeySize(suite)
	if expectedKeySize == 0 {
		return nil, fmt.Errorf("unsupported cipher suite: %s", suite)
	}

	if len(key) != expectedKeySize {
		return nil, fmt.Errorf("invalid key size for %s: expected %d, got %d",
			suite, expectedKeySize, len(key))
	}

	switch suite {
	case AES128GCM, AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("creating AES cipher for %s: %w", suite, err)
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("creating GCM for %s: %w", suite, err)
		}

		return aead, nil

	case CHACHA20POLY1305:
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			return nil, fmt.Errorf("creating ChaCha20-Poly1305: %w", err)
		}

		return aead, nil

	default:
		return nil, fmt.Errorf("unsupported cipher suite: %s", suite)
	}
}

// BuildNonce constructs the 12-byte AEAD nonce from a 4-byte salt and
// an 8-byte explicit IV. Per RFC 4106 §4 and RFC 7634 §3:
//
//	nonce = salt (4 bytes) || IV (8 bytes)
//
// The IV is typically the ESP sequence number (extended to 8 bytes).
func BuildNonce(salt []byte, iv []byte) ([]byte, error) {
	if len(salt) != 4 {
		return nil, fmt.Errorf("salt must be 4 bytes, got %d", len(salt))
	}

	if len(iv) != 8 {
		return nil, fmt.Errorf("IV must be 8 bytes, got %d", len(iv))
	}

	nonce := make([]byte, 12)

	copy(nonce[:4], salt)
	copy(nonce[4:], iv)

	return nonce, nil
}

// SequenceToIV converts a 64-bit sequence number to an 8-byte explicit IV
// in big-endian order.
func SequenceToIV(seqNum uint64) []byte {
	iv := make([]byte, 8)

	iv[0] = byte(seqNum >> 56)
	iv[1] = byte(seqNum >> 48)
	iv[2] = byte(seqNum >> 40)
	iv[3] = byte(seqNum >> 32)
	iv[4] = byte(seqNum >> 24)
	iv[5] = byte(seqNum >> 16)
	iv[6] = byte(seqNum >> 8)
	iv[7] = byte(seqNum)

	return iv
}
