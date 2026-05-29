package esp

import (
	"sync"
	"testing"
)

func TestBufferPoolGetPut(t *testing.T) {
	pool := NewBufferPool(4096)

	buf := pool.Get()
	if len(buf) != 4096 {
		t.Fatalf("expected buffer length 4096, got %d", len(buf))
	}

	for i := range buf {
		if buf[i] != 0 {
			t.Fatalf("buffer not zeroed at index %d", i)
		}
	}

	pool.Put(buf)
}

func TestBufferPoolGetZeroed(t *testing.T) {
	pool := NewBufferPool(256)

	buf := pool.Get()
	for i := range buf {
		buf[i] = 0xFF
	}
	pool.Put(buf)

	buf2 := pool.Get()
	for i := range buf2 {
		if buf2[i] != 0 {
			t.Fatalf("reused buffer not zeroed at index %d, got %d", i, buf2[i])
		}
	}
	pool.Put(buf2)
}

func TestBufferPoolRejectsWrongSize(t *testing.T) {
	pool := NewBufferPool(1024)

	wrongBuf := make([]byte, 512)
	pool.Put(wrongBuf) // should silently discard

	buf := pool.Get()
	if len(buf) != 1024 {
		t.Fatalf("expected buffer length 1024, got %d", len(buf))
	}
	pool.Put(buf)
}

func TestBufferPoolConcurrent(t *testing.T) {
	pool := NewBufferPool(MaxPacketSize)
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			buf := pool.Get()
			if len(buf) != MaxPacketSize {
				t.Errorf("expected buffer length %d, got %d", MaxPacketSize, len(buf))
			}

			buf[0] = 42
			pool.Put(buf)
		}()
	}

	wg.Wait()
}
