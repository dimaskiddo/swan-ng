package ike

import (
	"testing"
)

func TestSKFPayloadMarshalParse(t *testing.T) {
	original := &SKFPayload{
		FragmentNumber: 3,
		TotalFragments: 7,
		EncryptedData:  []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03},
	}

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Skip generic payload header (4 bytes).
	body := data[PayloadHeaderLen:]

	parsed, err := parseV2SKF(body)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if parsed.FragmentNumber != original.FragmentNumber {
		t.Errorf("FragmentNumber: got %d, want %d", parsed.FragmentNumber, original.FragmentNumber)
	}

	if parsed.TotalFragments != original.TotalFragments {
		t.Errorf("TotalFragments: got %d, want %d", parsed.TotalFragments, original.TotalFragments)
	}

	if len(parsed.EncryptedData) != len(original.EncryptedData) {
		t.Fatalf("EncryptedData length: got %d, want %d", len(parsed.EncryptedData), len(original.EncryptedData))
	}

	for i := range parsed.EncryptedData {
		if parsed.EncryptedData[i] != original.EncryptedData[i] {
			t.Errorf("EncryptedData[%d]: got 0x%02X, want 0x%02X", i, parsed.EncryptedData[i], original.EncryptedData[i])
		}
	}
}

func TestFragmentCacheBasic(t *testing.T) {
	cache := NewFragmentCache(42)

	// Add fragment 2/3.
	complete, err := cache.AddFragment(2, 3, []byte("world"))
	if err != nil {
		t.Fatalf("AddFragment(2/3): %v", err)
	}
	if complete {
		t.Fatal("should not be complete after 1/3")
	}

	// Add fragment 1/3.
	complete, err = cache.AddFragment(1, 3, []byte("hello"))
	if err != nil {
		t.Fatalf("AddFragment(1/3): %v", err)
	}
	if complete {
		t.Fatal("should not be complete after 2/3")
	}

	// Add fragment 3/3.
	complete, err = cache.AddFragment(3, 3, []byte("!"))
	if err != nil {
		t.Fatalf("AddFragment(3/3): %v", err)
	}
	if !complete {
		t.Fatal("should be complete after 3/3")
	}

	// Reassemble.
	result, err := cache.Reassemble()
	if err != nil {
		t.Fatalf("Reassemble: %v", err)
	}

	expected := "helloworld!"
	if string(result) != expected {
		t.Errorf("Reassembled: got %q, want %q", string(result), expected)
	}
}

func TestFragmentCacheInvalidInputs(t *testing.T) {
	cache := NewFragmentCache(1)

	// Fragment 0 invalid.
	_, err := cache.AddFragment(0, 3, []byte("x"))
	if err == nil {
		t.Error("expected error for fragment 0")
	}

	// Total 0 invalid.
	_, err = cache.AddFragment(1, 0, []byte("x"))
	if err == nil {
		t.Error("expected error for total 0")
	}

	// Fragment > total invalid.
	_, err = cache.AddFragment(5, 3, []byte("x"))
	if err == nil {
		t.Error("expected error for fragment > total")
	}
}

func TestFragmentCacheTotalMismatch(t *testing.T) {
	cache := NewFragmentCache(1)

	_, err := cache.AddFragment(1, 3, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}

	// Different total = error.
	_, err = cache.AddFragment(2, 5, []byte("b"))
	if err == nil {
		t.Error("expected error when total changes")
	}
}

func TestFragmentManagerGetOrCreate(t *testing.T) {
	fm := NewFragmentManager()

	spi := [16]byte{1, 2, 3}
	c1 := fm.GetOrCreate(spi, 100)
	c2 := fm.GetOrCreate(spi, 100)

	if c1 != c2 {
		t.Error("same key should return same cache")
	}

	c3 := fm.GetOrCreate(spi, 200)
	if c1 == c3 {
		t.Error("different msgID should return different cache")
	}

	fm.Remove(spi, 100)
	c4 := fm.GetOrCreate(spi, 100)
	if c1 == c4 {
		t.Error("after Remove, should get new cache")
	}
}
