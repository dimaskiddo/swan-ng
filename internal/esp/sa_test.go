package esp

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
)

func newTestSAHelper(t *testing.T, spi uint32) *SecurityAssociation {
	t.Helper()

	key := make([]byte, 16)
	salt := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	sa, err := NewTestSA(spi, AES128GCM, key, salt, &net.UDPAddr{
		IP:   net.IPv4(192, 168, 1, 1),
		Port: 4500,
	}, true)
	if err != nil {
		t.Fatal(err)
	}

	return sa
}

func TestSADatabaseAddLookup(t *testing.T) {
	db := NewSADatabase()
	sa := newTestSAHelper(t, 0x12345678)

	if err := db.AddInbound(sa); err != nil {
		t.Fatalf("AddInbound failed: %v", err)
	}

	got := db.LookupBySPI(0x12345678)
	if got == nil {
		t.Fatal("LookupBySPI returned nil")
	}
	if got.SPI != 0x12345678 {
		t.Fatalf("SPI mismatch: expected 0x12345678, got 0x%08X", got.SPI)
	}
}

func TestSADatabaseLookupMiss(t *testing.T) {
	db := NewSADatabase()

	got := db.LookupBySPI(0xDEADBEEF)
	if got != nil {
		t.Fatal("expected nil for missing SPI")
	}
}

func TestSADatabaseDuplicateSPI(t *testing.T) {
	db := NewSADatabase()
	sa1 := newTestSAHelper(t, 0xAAAAAAAA)
	sa2 := newTestSAHelper(t, 0xAAAAAAAA)

	if err := db.AddInbound(sa1); err != nil {
		t.Fatalf("first AddInbound failed: %v", err)
	}

	err := db.AddInbound(sa2)
	if err == nil {
		t.Fatal("expected error for duplicate SPI")
	}
}

func TestSADatabaseReservedSPI(t *testing.T) {
	db := NewSADatabase()

	// SPI 0 is reserved.
	sa0 := newTestSAHelper(t, 0)
	sa0.SPI = 0
	err := db.AddInbound(sa0)
	if err == nil {
		t.Fatal("expected error for SPI 0")
	}

	// SPI 100 is in reserved range 1-255.
	sa100 := newTestSAHelper(t, 100)
	sa100.SPI = 100
	err = db.AddInbound(sa100)
	if err == nil {
		t.Fatal("expected error for SPI 100 (reserved)")
	}
}

func TestSADatabaseRemoveInbound(t *testing.T) {
	db := NewSADatabase()
	sa := newTestSAHelper(t, 0xBBBBBBBB)

	if err := db.AddInbound(sa); err != nil {
		t.Fatal(err)
	}

	if db.InboundCount() != 1 {
		t.Fatalf("expected 1 inbound SA, got %d", db.InboundCount())
	}

	db.RemoveInbound(0xBBBBBBBB)

	if db.InboundCount() != 0 {
		t.Fatalf("expected 0 inbound SAs after removal, got %d", db.InboundCount())
	}

	if db.LookupBySPI(0xBBBBBBBB) != nil {
		t.Fatal("expected nil after removal")
	}
}

func TestSADatabaseOutbound(t *testing.T) {
	db := NewSADatabase()
	sa := newTestSAHelper(t, 0xCCCCCCCC)

	if err := db.AddOutbound(sa); err != nil {
		t.Fatal(err)
	}

	if db.OutboundCount() != 1 {
		t.Fatalf("expected 1 outbound SA, got %d", db.OutboundCount())
	}

	outbound := db.OutboundSAs()
	if len(outbound) != 1 {
		t.Fatalf("expected 1 outbound SA snapshot, got %d", len(outbound))
	}
	if outbound[0].SPI != 0xCCCCCCCC {
		t.Fatalf("outbound SPI mismatch")
	}

	db.RemoveOutbound(0xCCCCCCCC)

	if db.OutboundCount() != 0 {
		t.Fatalf("expected 0 outbound SAs after removal, got %d", db.OutboundCount())
	}
}

func TestSADatabaseConcurrent(t *testing.T) {
	db := NewSADatabase()
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)

		go func(idx int) {
			defer wg.Done()
			spi := uint32(0x10000 + idx)
			sa := newTestSAHelper(t, spi)

			if err := db.AddInbound(sa); err != nil {
				t.Errorf("AddInbound failed for SPI 0x%08X: %v", spi, err)
				return
			}

			got := db.LookupBySPI(spi)
			if got == nil {
				t.Errorf("LookupBySPI returned nil for SPI 0x%08X", spi)
			}
		}(i)
	}

	wg.Wait()

	if db.InboundCount() != 50 {
		t.Fatalf("expected 50 inbound SAs, got %d", db.InboundCount())
	}
}

func TestGenerateSPI(t *testing.T) {
	seen := make(map[uint32]bool)

	for i := 0; i < 100; i++ {
		spi, err := GenerateSPI()
		if err != nil {
			t.Fatalf("GenerateSPI failed: %v", err)
		}

		if spi <= 255 {
			t.Fatalf("generated SPI %d is in reserved range", spi)
		}

		if seen[spi] {
			t.Fatalf("duplicate SPI generated: 0x%08X", spi)
		}
		seen[spi] = true
	}
}

func TestNewTestSA(t *testing.T) {
	key := make([]byte, 16)
	salt := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	sa, err := NewTestSA(0x42424242, AES128GCM, key, salt, &net.UDPAddr{
		IP:   net.IPv4(10, 0, 0, 1),
		Port: 4500,
	}, true)
	if err != nil {
		t.Fatalf("NewTestSA failed: %v", err)
	}

	if sa.SPI != 0x42424242 {
		t.Fatal("SPI mismatch")
	}
	if sa.AEAD == nil {
		t.Fatal("AEAD should be initialized")
	}
	if sa.ReplayWindow == nil {
		t.Fatal("ReplayWindow should be initialized")
	}
	if !sa.TunnelMode {
		t.Fatal("TunnelMode should be true")
	}
}
