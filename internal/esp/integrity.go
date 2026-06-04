package esp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

// IntegritySuite identifies the HMAC algorithm for ESP ICV (Integrity Check Value).
type IntegritySuite uint8

const (
	// IntegNone indicates no separate integrity algorithm (used with AEAD ciphers).
	IntegNone IntegritySuite = 0

	// IntegHMAC_SHA1_96 uses HMAC-SHA1 truncated to 96 bits (12 bytes).
	// RFC 2404. Key: 20 bytes.
	IntegHMAC_SHA1_96 IntegritySuite = 1

	// IntegHMAC_SHA256_128 uses HMAC-SHA-256 truncated to 128 bits (16 bytes).
	// RFC 4868 §2.3. Key: 32 bytes.
	IntegHMAC_SHA256_128 IntegritySuite = 2

	// IntegHMAC_SHA384_192 uses HMAC-SHA-384 truncated to 192 bits (24 bytes).
	// RFC 4868 §2.5. Key: 48 bytes.
	IntegHMAC_SHA384_192 IntegritySuite = 3

	// IntegHMAC_SHA512_256 uses HMAC-SHA-512 truncated to 256 bits (32 bytes).
	// RFC 4868 §2.7. Key: 64 bytes.
	IntegHMAC_SHA512_256 IntegritySuite = 4
)

// String returns a human-readable integrity suite name.
func (is IntegritySuite) String() string {
	switch is {
	case IntegNone:
		return "NONE"

	case IntegHMAC_SHA1_96:
		return "HMAC-SHA1-96"

	case IntegHMAC_SHA256_128:
		return "HMAC-SHA256-128"

	case IntegHMAC_SHA384_192:
		return "HMAC-SHA384-192"

	case IntegHMAC_SHA512_256:
		return "HMAC-SHA512-256"

	default:
		return fmt.Sprintf("unknown-integ(%d)", is)
	}
}

// IntegrityKeySize returns the HMAC key size in bytes for the given suite.
func IntegrityKeySize(suite IntegritySuite) int {
	switch suite {
	case IntegHMAC_SHA1_96:
		return 20

	case IntegHMAC_SHA256_128:
		return 32

	case IntegHMAC_SHA384_192:
		return 48

	case IntegHMAC_SHA512_256:
		return 64

	default:
		return 0
	}
}

// IntegrityICVSize returns the truncated ICV output size in bytes.
func IntegrityICVSize(suite IntegritySuite) int {
	switch suite {
	case IntegHMAC_SHA1_96:
		return 12

	case IntegHMAC_SHA256_128:
		return 16

	case IntegHMAC_SHA384_192:
		return 24

	case IntegHMAC_SHA512_256:
		return 32

	default:
		return 0
	}
}

// IntegrityAlgorithm computes and verifies ESP ICV using HMAC.
type IntegrityAlgorithm struct {
	suite    IntegritySuite
	key      []byte
	hashFunc func() hash.Hash
	icvSize  int
}

// NewIntegrity creates an IntegrityAlgorithm for the given suite and key.
func NewIntegrity(suite IntegritySuite, key []byte) (*IntegrityAlgorithm, error) {
	expectedKeySize := IntegrityKeySize(suite)
	if expectedKeySize == 0 {
		return nil, fmt.Errorf("unsupported integrity suite: %s", suite)
	}

	if len(key) != expectedKeySize {
		return nil, fmt.Errorf("invalid key size for %s: expected %d, got %d", suite, expectedKeySize, len(key))
	}

	var hashFunc func() hash.Hash
	switch suite {
	case IntegHMAC_SHA1_96:
		hashFunc = sha1.New

	case IntegHMAC_SHA256_128:
		hashFunc = sha256.New

	case IntegHMAC_SHA384_192:
		hashFunc = sha512.New384

	case IntegHMAC_SHA512_256:
		hashFunc = sha512.New

	default:
		return nil, fmt.Errorf("unsupported integrity suite: %s", suite)
	}

	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &IntegrityAlgorithm{
		suite:    suite,
		key:      keyCopy,
		hashFunc: hashFunc,
		icvSize:  IntegrityICVSize(suite),
	}, nil
}

// Suite returns the integrity suite identifier.
func (ia *IntegrityAlgorithm) Suite() IntegritySuite {
	return ia.suite
}

// ICVSize returns the truncated ICV output size in bytes.
func (ia *IntegrityAlgorithm) ICVSize() int {
	return ia.icvSize
}

// Compute calculates the truncated HMAC over data.
// Returns a slice of ICVSize() bytes.
func (ia *IntegrityAlgorithm) Compute(data []byte) []byte {
	h := hmac.New(ia.hashFunc, ia.key)
	h.Write(data)

	full := h.Sum(nil)

	result := make([]byte, ia.icvSize)
	copy(result, full[:ia.icvSize])

	return result
}

// Verify checks that the provided ICV matches the HMAC of data.
// Uses constant-time comparison to prevent timing attacks.
func (ia *IntegrityAlgorithm) Verify(data, icv []byte) bool {
	if len(icv) != ia.icvSize {
		return false
	}

	computed := ia.Compute(data)

	return hmac.Equal(computed, icv)
}
