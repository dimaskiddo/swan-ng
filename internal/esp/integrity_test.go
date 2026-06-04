package esp

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestIntegrityKeySize(t *testing.T) {
	tests := []struct {
		suite    IntegritySuite
		expected int
	}{
		{IntegNone, 0},
		{IntegHMAC_SHA1_96, 20},
		{IntegHMAC_SHA256_128, 32},
		{IntegHMAC_SHA384_192, 48},
		{IntegHMAC_SHA512_256, 64},
	}

	for _, tt := range tests {
		got := IntegrityKeySize(tt.suite)
		if got != tt.expected {
			t.Errorf("IntegrityKeySize(%s): got %d, want %d", tt.suite, got, tt.expected)
		}
	}
}

func TestIntegrityICVSize(t *testing.T) {
	tests := []struct {
		suite    IntegritySuite
		expected int
	}{
		{IntegNone, 0},
		{IntegHMAC_SHA1_96, 12},
		{IntegHMAC_SHA256_128, 16},
		{IntegHMAC_SHA384_192, 24},
		{IntegHMAC_SHA512_256, 32},
	}

	for _, tt := range tests {
		got := IntegrityICVSize(tt.suite)
		if got != tt.expected {
			t.Errorf("IntegrityICVSize(%s): got %d, want %d", tt.suite, got, tt.expected)
		}
	}
}

func TestNewIntegrity_InvalidKeySize(t *testing.T) {
	_, err := NewIntegrity(IntegHMAC_SHA1_96, []byte("short"))
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestNewIntegrity_UnsupportedSuite(t *testing.T) {
	_, err := NewIntegrity(IntegNone, nil)
	if err == nil {
		t.Fatal("expected error for IntegNone")
	}
}

func testIntegrityRoundTrip(t *testing.T, suite IntegritySuite) {
	t.Helper()

	keySize := IntegrityKeySize(suite)
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	ia, err := NewIntegrity(suite, key)
	if err != nil {
		t.Fatalf("NewIntegrity(%s): %v", suite, err)
	}

	// Verify ICVSize.
	expectedICVSize := IntegrityICVSize(suite)
	if ia.ICVSize() != expectedICVSize {
		t.Errorf("ICVSize: got %d, want %d", ia.ICVSize(), expectedICVSize)
	}

	// Compute ICV over test data.
	data := []byte("ESP packet header + IV + ciphertext for HMAC verification")
	icv := ia.Compute(data)

	if len(icv) != expectedICVSize {
		t.Errorf("Compute output length: got %d, want %d", len(icv), expectedICVSize)
	}

	// Verify should succeed with correct ICV.
	if !ia.Verify(data, icv) {
		t.Error("Verify failed with correct ICV")
	}

	// Verify should fail with corrupted ICV.
	badICV := make([]byte, len(icv))
	copy(badICV, icv)
	badICV[0] ^= 0xFF

	if ia.Verify(data, badICV) {
		t.Error("Verify succeeded with corrupted ICV")
	}

	// Verify should fail with corrupted data.
	badData := make([]byte, len(data))
	copy(badData, data)
	badData[0] ^= 0xFF

	if ia.Verify(badData, icv) {
		t.Error("Verify succeeded with corrupted data")
	}

	// Verify should fail with wrong-length ICV.
	if ia.Verify(data, icv[:len(icv)-1]) {
		t.Error("Verify succeeded with truncated ICV")
	}
}

func TestIntegrity_HMAC_SHA1_96(t *testing.T) {
	testIntegrityRoundTrip(t, IntegHMAC_SHA1_96)
}

func TestIntegrity_HMAC_SHA256_128(t *testing.T) {
	testIntegrityRoundTrip(t, IntegHMAC_SHA256_128)
}

func TestIntegrity_HMAC_SHA384_192(t *testing.T) {
	testIntegrityRoundTrip(t, IntegHMAC_SHA384_192)
}

func TestIntegrity_HMAC_SHA512_256(t *testing.T) {
	testIntegrityRoundTrip(t, IntegHMAC_SHA512_256)
}

func TestIntegrity_DifferentKeysProduceDifferentICV(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)

	if _, err := rand.Read(key1); err != nil {
		t.Fatal(err)
	}

	if _, err := rand.Read(key2); err != nil {
		t.Fatal(err)
	}

	ia1, _ := NewIntegrity(IntegHMAC_SHA256_128, key1)
	ia2, _ := NewIntegrity(IntegHMAC_SHA256_128, key2)

	data := []byte("test data for different keys")
	icv1 := ia1.Compute(data)
	icv2 := ia2.Compute(data)

	if bytes.Equal(icv1, icv2) {
		t.Error("different keys produced identical ICVs")
	}
}
