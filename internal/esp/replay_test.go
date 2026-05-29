package esp

import "testing"

func TestReplayWindowFirstPacket(t *testing.T) {
	rw := NewReplayWindow(64)

	if !rw.Check(1) {
		t.Fatal("first packet should be accepted")
	}

	rw.Advance(1)

	if rw.lastSeq != 1 {
		t.Fatalf("expected lastSeq=1, got %d", rw.lastSeq)
	}
}

func TestReplayWindowSequentialAccept(t *testing.T) {
	rw := NewReplayWindow(64)

	for i := uint64(1); i <= 100; i++ {
		if !rw.Check(i) {
			t.Fatalf("packet %d should be accepted", i)
		}
		rw.Advance(i)
	}

	if rw.lastSeq != 100 {
		t.Fatalf("expected lastSeq=100, got %d", rw.lastSeq)
	}
}

func TestReplayWindowDuplicateReject(t *testing.T) {
	rw := NewReplayWindow(64)

	rw.Advance(1)

	if rw.Check(1) {
		t.Fatal("duplicate packet 1 should be rejected")
	}
}

func TestReplayWindowOutOfOrder(t *testing.T) {
	rw := NewReplayWindow(64)

	// Receive packets 1, 2, 5, 3, 4.
	rw.Advance(1)
	rw.Advance(2)
	rw.Advance(5)

	if !rw.Check(3) {
		t.Fatal("out-of-order packet 3 should be accepted")
	}
	rw.Advance(3)

	if !rw.Check(4) {
		t.Fatal("out-of-order packet 4 should be accepted")
	}
	rw.Advance(4)

	// Duplicates of already-seen packets.
	if rw.Check(3) {
		t.Fatal("duplicate packet 3 should be rejected")
	}
	if rw.Check(5) {
		t.Fatal("duplicate packet 5 should be rejected")
	}
}

func TestReplayWindowTooOld(t *testing.T) {
	rw := NewReplayWindow(64)

	// Advance window far ahead.
	rw.Advance(100)

	// Packet 35 is within window (100-64=36, so 36..100 valid; 35 is too old).
	if rw.Check(35) {
		t.Fatal("packet 35 should be too old (window: 37..100)")
	}

	// Packet 36 is still within window.
	if rw.Check(36) {
		t.Fatal("packet 36 should be too old (window: 37..100)")
	}

	// Packet 37 is within window.
	if !rw.Check(37) {
		t.Fatal("packet 37 should be accepted (within window)")
	}
}

func TestReplayWindowZeroSeq(t *testing.T) {
	rw := NewReplayWindow(64)

	if rw.Check(0) {
		t.Fatal("sequence number 0 should always be rejected")
	}
}

func TestReplayWindowLargeGap(t *testing.T) {
	rw := NewReplayWindow(128)

	rw.Advance(1)
	rw.Advance(200)

	// Packet 1 is now far outside the window.
	if rw.Check(1) {
		t.Fatal("packet 1 should be outside window after large gap")
	}

	// Packet 199 is within window.
	if !rw.Check(199) {
		t.Fatal("packet 199 should be within window")
	}
	rw.Advance(199)
}

func TestReplayWindowRoundUpSize(t *testing.T) {
	rw := NewReplayWindow(100)

	// 100 rounds up to 128 (2 * 64).
	if rw.size != 128 {
		t.Fatalf("expected size rounded to 128, got %d", rw.size)
	}
	if len(rw.bitmap) != 2 {
		t.Fatalf("expected 2 bitmap words, got %d", len(rw.bitmap))
	}
}

func TestReplayWindowDefaultSize(t *testing.T) {
	rw := NewReplayWindow(0)

	if rw.size != DefaultReplayWindowSize {
		t.Fatalf("expected default size %d, got %d", DefaultReplayWindowSize, rw.size)
	}
}
