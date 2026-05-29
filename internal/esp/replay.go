package esp

import "sync"

const (
	// DefaultReplayWindowSize is the default anti-replay window size in packets.
	// RFC 4303 §3.4.3 recommends minimum 64; we default to 128 for high-speed.
	DefaultReplayWindowSize = 128
)

// ReplayWindow implements the anti-replay sliding window per RFC 4303 §3.4.3
// and Appendix A. It detects duplicate and out-of-order packets using a
// bitmap. Thread-safe via mutex.
type ReplayWindow struct {
	mu      sync.Mutex
	bitmap  []uint64 // bit array, each uint64 holds 64 bits
	lastSeq uint64   // highest validated sequence number (T)
	size    uint32   // window size in packets
}

// NewReplayWindow creates a replay window with the given size.
// Size must be a multiple of 64; if not, it's rounded up.
func NewReplayWindow(size uint32) *ReplayWindow {
	if size == 0 {
		size = DefaultReplayWindowSize
	}

	// Round up to next multiple of 64.
	words := (size + 63) / 64
	size = words * 64

	return &ReplayWindow{
		bitmap:  make([]uint64, words),
		lastSeq: 0,
		size:    size,
	}
}

// Check tests whether a packet with the given sequence number is acceptable.
// Returns true if the packet should be processed (not a replay, within window).
// Does NOT update state — call Advance after successful integrity verification.
//
// Per RFC 4303 §3.4.3: "This SHOULD be the first ESP check applied to a
// packet after it has been matched to an SA, to speed rejection of duplicate
// packets."
func (rw *ReplayWindow) Check(seq uint64) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if seq == 0 {
		// Sequence number 0 is never valid (first packet is 1).
		return false
	}

	if rw.lastSeq == 0 {
		// First packet ever — any non-zero seq is acceptable.
		return true
	}

	if seq > rw.lastSeq {
		// To the right of the window — always acceptable.
		return true
	}

	// How far back is this packet from the highest seen?
	diff := rw.lastSeq - seq
	if diff >= uint64(rw.size) {
		// Too old — falls before the left edge of the window.
		return false
	}

	// Check if this position's bit is already set (duplicate).
	wordIndex := diff / 64
	bitIndex := diff % 64

	if wordIndex >= uint64(len(rw.bitmap)) {
		return false
	}

	if rw.bitmap[wordIndex]&(1<<bitIndex) != 0 {
		// Duplicate — bit already set.
		return false
	}

	return true
}

// Advance updates the replay window after a packet's integrity has been
// verified. Must only be called after a successful integrity check.
func (rw *ReplayWindow) Advance(seq uint64) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if seq == 0 {
		return
	}

	if rw.lastSeq == 0 {
		// First packet — initialize window.
		rw.lastSeq = seq
		rw.setBit(0)

		return
	}

	if seq > rw.lastSeq {
		// Shift window right by (seq - lastSeq) positions.
		shift := seq - rw.lastSeq
		rw.shiftBitmap(shift)

		rw.lastSeq = seq
		rw.setBit(0)

		return
	}

	// Packet within window — set its bit.
	diff := rw.lastSeq - seq
	if diff < uint64(rw.size) {
		rw.setBit(diff)
	}
}

// setBit sets the bit at the given offset from the right edge (lastSeq).
func (rw *ReplayWindow) setBit(offset uint64) {
	wordIndex := offset / 64
	bitIndex := offset % 64

	if wordIndex < uint64(len(rw.bitmap)) {
		rw.bitmap[wordIndex] |= 1 << bitIndex
	}
}

// shiftBitmap shifts the entire bitmap right by n positions,
// effectively moving the window forward.
func (rw *ReplayWindow) shiftBitmap(n uint64) {
	words := uint64(len(rw.bitmap))

	if n >= uint64(rw.size) {
		// Shift exceeds window — clear everything.
		clear(rw.bitmap)
		return
	}

	wordShift := n / 64
	bitShift := n % 64

	if wordShift > 0 {
		// Shift whole words first.
		for i := words - 1; i >= wordShift; i-- {
			rw.bitmap[i] = rw.bitmap[i-wordShift]
		}

		for i := uint64(0); i < wordShift && i < words; i++ {
			rw.bitmap[i] = 0
		}
	}

	if bitShift > 0 {
		// Shift remaining bits within words.
		for i := words - 1; i > 0; i-- {
			rw.bitmap[i] = (rw.bitmap[i] << bitShift) | (rw.bitmap[i-1] >> (64 - bitShift))
		}

		rw.bitmap[0] <<= bitShift
	}
}
