package ipam

import (
	"net"
	"sync"
	"testing"
)

func TestNewPool(t *testing.T) {
	tests := []struct {
		name     string
		rangeStr string
		wantSize int
		wantErr  bool
	}{
		{"valid small range", "10.0.0.10 - 10.0.0.20", 11, false},
		{"valid single IP", "10.0.0.1 - 10.0.0.1", 1, false},
		{"valid large range", "10.0.0.1 - 10.0.0.254", 254, false},
		{"reversed range", "10.0.0.20 - 10.0.0.10", 0, true},
		{"invalid format", "10.0.0.10", 0, true},
		{"invalid start IP", "bad - 10.0.0.20", 0, true},
		{"invalid end IP", "10.0.0.10 - bad", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := NewPool(tt.rangeStr)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pool.Size() != tt.wantSize {
				t.Errorf("size = %d, want %d", pool.Size(), tt.wantSize)
			}
			if pool.Available() != tt.wantSize {
				t.Errorf("available = %d, want %d", pool.Available(), tt.wantSize)
			}
		})
	}
}

func TestAllocateAndRelease(t *testing.T) {
	pool, err := NewPool("10.0.0.10 - 10.0.0.14")
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	// Allocate all 5 IPs.
	allocated := make([]net.IP, 0, 5)
	for i := 0; i < 5; i++ {
		ip, err := pool.Allocate()
		if err != nil {
			t.Fatalf("Allocate[%d]: %v", i, err)
		}
		allocated = append(allocated, ip)
	}

	// Verify sequential allocation.
	expected := []string{"10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14"}
	for i, ip := range allocated {
		if ip.String() != expected[i] {
			t.Errorf("allocated[%d] = %s, want %s", i, ip, expected[i])
		}
	}

	// Pool should be exhausted.
	if pool.Available() != 0 {
		t.Errorf("available = %d, want 0", pool.Available())
	}
	_, err = pool.Allocate()
	if err == nil {
		t.Fatal("expected pool exhaustion error")
	}

	// Release one IP and re-allocate.
	if err := pool.Release(net.ParseIP("10.0.0.12")); err != nil {
		t.Fatalf("Release: %v", err)
	}
	if pool.Available() != 1 {
		t.Errorf("available after release = %d, want 1", pool.Available())
	}

	ip, err := pool.Allocate()
	if err != nil {
		t.Fatalf("re-Allocate: %v", err)
	}
	if ip.String() != "10.0.0.12" {
		t.Errorf("re-allocated = %s, want 10.0.0.12", ip)
	}
}

func TestAllocateSpecific(t *testing.T) {
	pool, err := NewPool("10.0.0.10 - 10.0.0.14")
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	// Allocate specific IP.
	if err := pool.AllocateSpecific(net.ParseIP("10.0.0.12")); err != nil {
		t.Fatalf("AllocateSpecific: %v", err)
	}

	// Double allocate should fail.
	if err := pool.AllocateSpecific(net.ParseIP("10.0.0.12")); err == nil {
		t.Fatal("expected error for double allocation")
	}

	// Out of range should fail.
	if err := pool.AllocateSpecific(net.ParseIP("10.0.0.100")); err == nil {
		t.Fatal("expected error for out-of-range IP")
	}
}

func TestReleaseErrors(t *testing.T) {
	pool, err := NewPool("10.0.0.10 - 10.0.0.14")
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	// Release unallocated IP should fail.
	if err := pool.Release(net.ParseIP("10.0.0.10")); err == nil {
		t.Fatal("expected error for releasing unallocated IP")
	}

	// Release out-of-range IP should fail.
	if err := pool.Release(net.ParseIP("10.0.0.100")); err == nil {
		t.Fatal("expected error for out-of-range IP")
	}
}

func TestConcurrentAllocation(t *testing.T) {
	pool, err := NewPool("10.0.0.1 - 10.0.0.100")
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan net.IP, 100)
	errors := make(chan error, 100)

	// Spawn 100 goroutines each trying to allocate.
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ip, err := pool.Allocate()
			if err != nil {
				errors <- err
				return
			}
			results <- ip
		}()
	}

	wg.Wait()
	close(results)
	close(errors)

	// All 100 should succeed with no errors.
	if len(errors) > 0 {
		t.Fatalf("got %d allocation errors, expected 0", len(errors))
	}

	// Check all IPs are unique.
	seen := make(map[string]bool)
	for ip := range results {
		s := ip.String()
		if seen[s] {
			t.Fatalf("duplicate IP allocated: %s", s)
		}
		seen[s] = true
	}

	if len(seen) != 100 {
		t.Errorf("allocated %d unique IPs, want 100", len(seen))
	}

	if pool.Available() != 0 {
		t.Errorf("available = %d, want 0", pool.Available())
	}
}
