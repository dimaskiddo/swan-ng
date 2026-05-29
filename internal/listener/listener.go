package listener

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/dimaskiddo/swan-ng/internal/esp"
	"github.com/dimaskiddo/swan-ng/internal/log"
)

const (
	// PortIKE is the standard IKEv2 control port (RFC 7296).
	PortIKE = 500

	// PortNATT is the IPsec NAT-T port for UDP-encapsulated ESP (RFC 3948).
	PortNATT = 4500

	// PortL2TP is the L2TP control/data port (RFC 2661).
	PortL2TP = 1701

	// maxUDPPacketSize is the maximum UDP datagram size.
	maxUDPPacketSize = 65536
)

// PacketHandler is called when a UDP packet is received.
// buf contains the packet data with length n.
// remoteAddr is the sender's address.
// The handler MUST NOT retain buf after returning — copy if needed.
type PacketHandler func(buf []byte, n int, remoteAddr *net.UDPAddr)

// UDPListener manages a single UDP listener on a specific port.
type UDPListener struct {
	conn    *net.UDPConn
	port    int
	pool    *esp.BufferPool
	handler PacketHandler
	label   string // human-readable label for logging
}

// Manager coordinates all UDP listeners for the SWAN-NG daemon.
// Manages listeners on ports 500 (IKE), 4500 (NAT-T/ESP), and 1701 (L2TP).
type Manager struct {
	listeners []*UDPListener
	pool      *esp.BufferPool
	mu        sync.Mutex
	running   bool
}

// NewManager creates a listener manager with a shared buffer pool.
func NewManager(pool *esp.BufferPool) *Manager {
	return &Manager{
		pool:      pool,
		listeners: make([]*UDPListener, 0, 3),
	}
}

// AddUDP creates and binds a UDP listener on the specified address and port.
// The handler is called for each received packet.
func (m *Manager) AddUDP(listenAddr string, port int, label string, handler PacketHandler) error {
	addr := &net.UDPAddr{
		IP:   net.ParseIP(listenAddr),
		Port: port,
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("binding UDP %s:%d (%s): %w", listenAddr, port, label, err)
	}

	// Capture actual bound port (important for ephemeral port 0).
	actualPort := conn.LocalAddr().(*net.UDPAddr).Port

	l := &UDPListener{
		conn:    conn,
		port:    actualPort,
		pool:    m.pool,
		handler: handler,
		label:   label,
	}

	m.mu.Lock()
	m.listeners = append(m.listeners, l)
	m.mu.Unlock()

	log.Info("UDP listener bound",
		"label", label,
		"addr", addr.String(),
	)

	return nil
}

// Start begins receiving packets on all listeners.
// Each listener runs in its own goroutine. Blocks until ctx is cancelled.
func (m *Manager) Start(ctx context.Context) {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.mu.Unlock()

	var wg sync.WaitGroup

	for _, l := range m.listeners {
		wg.Add(1)

		go func(listener *UDPListener) {
			defer wg.Done()
			listener.readLoop(ctx)
		}(l)
	}

	log.Info("all UDP listeners started", "count", len(m.listeners))

	// Wait for context cancellation.
	<-ctx.Done()

	// Close all connections to unblock read loops.
	m.closeAll()

	// Wait for all read loops to finish.
	wg.Wait()

	log.Info("all UDP listeners stopped")
}

// SendTo sends a UDP packet to the specified remote address via the listener
// on the given port.
func (m *Manager) SendTo(port int, data []byte, remoteAddr *net.UDPAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, l := range m.listeners {
		if l.port == port {
			_, err := l.conn.WriteToUDP(data, remoteAddr)
			if err != nil {
				return fmt.Errorf("UDP send to %s on port %d: %w", remoteAddr, port, err)
			}

			return nil
		}
	}

	return fmt.Errorf("no listener found for port %d", port)
}

// GetConn returns the underlying UDP connection for a given port.
// Returns nil if no listener is bound to that port.
func (m *Manager) GetConn(port int) *net.UDPConn {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, l := range m.listeners {
		if l.port == port {
			return l.conn
		}
	}

	return nil
}

// closeAll closes all listener connections.
func (m *Manager) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, l := range m.listeners {
		if err := l.conn.Close(); err != nil {
			log.Debug("error closing UDP listener",
				"label", l.label,
				"port", l.port,
				"error", err.Error(),
			)
		}
	}
}

// readLoop is the per-listener receive loop. Uses buffer pool for zero-alloc
// packet processing per AGENTS.md §10.
func (l *UDPListener) readLoop(ctx context.Context) {
	log.Info("UDP read loop started",
		"label", l.label,
		"port", l.port,
	)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		buf := l.pool.Get()

		n, remoteAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			l.pool.Put(buf)

			// Check if context cancelled (normal shutdown).
			select {
			case <-ctx.Done():
				return
			default:
			}

			log.Debug("UDP read error",
				"label", l.label,
				"port", l.port,
				"error", err.Error(),
			)

			continue
		}

		if n == 0 {
			l.pool.Put(buf)
			continue
		}

		// Call handler synchronously. Handler must not retain buf.
		l.handler(buf, n, remoteAddr)

		l.pool.Put(buf)
	}
}
