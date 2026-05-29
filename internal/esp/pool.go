package esp

import "sync"

const (
	// MaxPacketSize is the maximum buffer size for a single UDP datagram.
	// UDP theoretical max is 65535 but practical ESP packets are much smaller.
	MaxPacketSize = 65536

	// DefaultMTU is the default TUN interface MTU.
	DefaultMTU = 1280

	// ESPHeaderLen is the fixed-size ESP header: SPI (4) + SeqNum (4).
	ESPHeaderLen = 8

	// ESPTrailerMinLen is the minimum ESP trailer: PadLength (1) + NextHeader (1).
	ESPTrailerMinLen = 2
)

// BufferPool provides reusable byte buffers for high-throughput packet
// processing. Uses sync.Pool to minimize GC pressure per AGENTS.md §10.
type BufferPool struct {
	pool sync.Pool
	size int
}

// NewBufferPool creates a buffer pool with fixed-size buffers.
func NewBufferPool(bufferSize int) *BufferPool {
	bp := &BufferPool{size: bufferSize}

	bp.pool = sync.Pool{
		New: func() any {
			buf := make([]byte, bufferSize)
			return &buf
		},
	}

	return bp
}

// Get returns a zeroed buffer from the pool.
// Caller MUST return the buffer via Put when done.
func (bp *BufferPool) Get() []byte {
	bufPtr := bp.pool.Get().(*[]byte)
	buf := *bufPtr

	// Zero the buffer to prevent data leaks between uses.
	clear(buf)

	return buf
}

// Put returns a buffer to the pool.
// Buffers with wrong size are silently discarded to prevent corruption.
func (bp *BufferPool) Put(buf []byte) {
	if cap(buf) != bp.size {
		return
	}

	buf = buf[:bp.size]
	bp.pool.Put(&buf)
}
