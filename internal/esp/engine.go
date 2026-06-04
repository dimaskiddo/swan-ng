package esp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// TUNReader reads raw IP packets from a virtual TUN device.
type TUNReader interface {
	ReadPacket(buf []byte) (int, error)
}

// TUNWriter writes raw IP packets to a virtual TUN device.
type TUNWriter interface {
	WritePacket(buf []byte, n int) error
}

// UDPSender sends UDP datagrams to a remote peer.
type UDPSender interface {
	SendTo(port int, data []byte, remoteAddr *net.UDPAddr) error
}

// L2TPHandler handles L2TP packets extracted from transport-mode ESP.
// The data parameter contains raw L2TP bytes (UDP payload, after UDP header stripped).
type L2TPHandler interface {
	HandlePacket(data []byte, peerAddr *net.UDPAddr)
}

// Engine is the user-space ESP data plane orchestrator.
// It bridges TUN ↔ ESP ↔ UDP for bidirectional packet flow:
//
//   - Inbound:  UDP:4500 → NAT-T classify → SA lookup by SPI → Decrypt → TUN write
//   - Outbound: TUN read → default SA → Encrypt → UDP send to peer
//
// Phase 3 uses a "default outbound SA" for routing. Phase 5 (IKEv2) will
// replace this with a proper Security Policy Database (SPD).
type Engine struct {
	saDB         *SADatabase
	pool         *BufferPool
	tunReader    TUNReader
	tunWriter    TUNWriter
	udpSender    UDPSender
	defaultOutSA *SecurityAssociation // Phase 3: simple outbound SA for testing
	nattPort     int                  // Port for sending ESP over NAT-T (4500)
	l2tpHandler  L2TPHandler          // L2TP handler for transport-mode packets

	// spd maps destination IP strings (string(IP.To16())) to Outbound SAs.
	spd map[string]*SecurityAssociation

	mu      sync.Mutex
	running bool
}

// EngineConfig holds configuration for the ESP engine.
type EngineConfig struct {
	// SADatabase is the Security Association database for inbound SPI lookups.
	SADatabase *SADatabase

	// Pool is the buffer pool for zero-alloc packet handling.
	Pool *BufferPool

	// TUNReader reads raw IP packets from the TUN device.
	TUNReader TUNReader

	// TUNWriter writes raw IP packets to the TUN device.
	TUNWriter TUNWriter

	// UDPSender sends ESP packets over UDP to remote peers.
	UDPSender UDPSender

	// DefaultOutboundSA is the default SA used for outbound traffic.
	// Phase 3 only — Phase 5 will use SPD-based routing.
	DefaultOutboundSA *SecurityAssociation

	// NATTPort is the UDP port used for NAT-T encapsulated ESP (default 4500).
	NATTPort int
}

// NewEngine creates a new ESP data plane engine.
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.SADatabase == nil {
		return nil, fmt.Errorf("SADatabase is required")
	}

	if cfg.Pool == nil {
		return nil, fmt.Errorf("BufferPool is required")
	}

	nattPort := cfg.NATTPort
	if nattPort == 0 {
		nattPort = 4500
	}

	return &Engine{
		saDB:         cfg.SADatabase,
		pool:         cfg.Pool,
		tunReader:    cfg.TUNReader,
		tunWriter:    cfg.TUNWriter,
		udpSender:    cfg.UDPSender,
		defaultOutSA: cfg.DefaultOutboundSA,
		nattPort:     nattPort,
		spd:          make(map[string]*SecurityAssociation),
	}, nil
}

// SetDefaultOutboundSA sets or replaces the default outbound SA.
// Thread-safe — can be called while the engine is running.
func (e *Engine) SetDefaultOutboundSA(sa *SecurityAssociation) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.defaultOutSA = sa

	if sa != nil {
		log.Info("default outbound SA updated",
			"spi", fmt.Sprintf("0x%08X", sa.SPI),
			"cipher", sa.CipherSuite.String(),
			"peer", sa.PeerAddr,
		)
	}
}

// SetL2TPHandler sets the handler for L2TP packets received via transport-mode ESP.
// When an ESP packet decrypts to nextHeader=UDP with dst_port=1701, the payload
// is routed to this handler instead of the TUN device.
func (e *Engine) SetL2TPHandler(h L2TPHandler) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.l2tpHandler = h
	log.Info("L2TP handler registered with ESP engine")
}

// AddOutboundSA registers an outbound SA for a specific destination IP (Basic SPD).
func (e *Engine) AddOutboundSA(dstIP net.IP, sa *SecurityAssociation) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.spd[string(dstIP.To16())] = sa

	log.Debug("ESP SPD: outbound SA registered", "dst_ip", dstIP.String(), "spi", fmt.Sprintf("0x%08X", sa.SPI))
}

// RemoveOutboundSA removes the outbound SA for a specific destination IP.
func (e *Engine) RemoveOutboundSA(dstIP net.IP) {
	e.mu.Lock()
	defer e.mu.Unlock()

	delete(e.spd, string(dstIP.To16()))

	log.Debug("ESP SPD: outbound SA removed", "dst_ip", dstIP.String())
}

// AddInboundSA registers an inbound SA in the SADatabase.
func (e *Engine) AddInboundSA(sa *SecurityAssociation) {
	if e.saDB != nil {
		e.saDB.AddInbound(sa)
		log.Debug("ESP SPD: inbound SA registered", "spi", fmt.Sprintf("0x%08X", sa.SPI))
	}
}

// RemoveInboundSA removes an inbound SA from the SADatabase.
func (e *Engine) RemoveInboundSA(spi uint32) {
	if e.saDB != nil {
		e.saDB.RemoveInbound(spi)
		log.Debug("ESP SPD: inbound SA removed", "spi", fmt.Sprintf("0x%08X", spi))
	}
}

// Start begins the bidirectional packet processing loops.
// Runs until ctx is cancelled. Blocks the calling goroutine.
func (e *Engine) Start(ctx context.Context) {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.mu.Unlock()

	var wg sync.WaitGroup

	// Start outbound loop (TUN → ESP → UDP) if TUN reader is available.
	if e.tunReader != nil {
		wg.Add(1)

		go func() {
			defer wg.Done()
			e.outboundLoop(ctx)
		}()

		log.Info("ESP engine outbound loop started")
	}

	log.Info("ESP engine started")

	<-ctx.Done()

	wg.Wait()

	e.mu.Lock()
	e.running = false
	e.mu.Unlock()

	log.Info("ESP engine stopped")
}

// HandleInboundESP processes an incoming ESP packet received from UDP.
// Called by the listener manager's handler for port 4500.
//
// Flow: Classify NAT-T → Parse SPI → SA lookup → Decrypt → Write to TUN.
//
// Per AGENTS.md §12: on any failure, log at Debug/Warn and silently drop.
func (e *Engine) HandleInboundESP(buf []byte, n int, remoteAddr *net.UDPAddr) {
	if n < ESPHeaderLen {
		log.Debug("inbound packet too short for ESP",
			"size", n,
			"from", remoteAddr,
		)

		return
	}

	// Classify NAT-T (port 4500 packets).
	pktType, espData, err := ClassifyNATT(buf[:n])
	if err != nil {
		log.Debug("NAT-T classification failed",
			"from", remoteAddr,
			"error", err.Error(),
		)

		return
	}

	if pktType == PacketTypeIKE {
		// IKE packets are handled by IKEv2 engine (Phase 5).
		log.Debug("IKE packet received, deferring to IKEv2 engine",
			"from", remoteAddr,
			"size", len(espData),
		)

		return
	}

	// Parse ESP header to get SPI.
	hdr, err := ParseHeader(espData)
	if err != nil {
		log.Debug("ESP header parse failed",
			"from", remoteAddr,
			"error", err.Error(),
		)

		return
	}

	// Lookup inbound SA by SPI.
	sa := e.saDB.LookupBySPI(hdr.SPI)
	if sa == nil {
		log.Debug("no SA found for SPI",
			"spi", fmt.Sprintf("0x%08X", hdr.SPI),
			"from", remoteAddr,
		)

		return
	}

	// Decrypt ESP packet.
	innerPacket, nextHeader, err := Decrypt(sa, espData)
	if err != nil {
		log.Debug("ESP decrypt failed",
			"spi", fmt.Sprintf("0x%08X", hdr.SPI),
			"from", remoteAddr,
			"error", err.Error(),
		)

		return
	}

	// Update peer address if changed (NAT rebinding).
	if sa.PeerAddr != nil && !sa.PeerAddr.IP.Equal(remoteAddr.IP) {
		log.Info("peer address updated (NAT rebinding)",
			"spi", fmt.Sprintf("0x%08X", hdr.SPI),
			"old_peer", sa.PeerAddr,
			"new_peer", remoteAddr,
		)

		sa.PeerAddr = remoteAddr
	}

	// Route based on nextHeader.
	switch nextHeader {
	case NextHeaderUDP:
		// Transport-mode ESP: inner payload is a UDP datagram.
		// Check for L2TP (dst port 1701) and route to L2TP handler.
		e.handleInnerUDP(innerPacket, remoteAddr, hdr.SPI)
	case NextHeaderDummy:
		// Discard dummy packets (RFC 4303 §2.6).
		return
	default:
		// IPv4/IPv6 or other — write to TUN.
		if e.tunWriter != nil && innerPacket != nil {
			if err := e.tunWriter.WritePacket(innerPacket, len(innerPacket)); err != nil {
				log.Warn("TUN write failed",
					"spi", fmt.Sprintf("0x%08X", hdr.SPI),
					"error", err.Error(),
				)
			}
		}
	}
}

// handleInnerUDP processes an inner UDP datagram from transport-mode ESP.
// If dst port is 1701 (L2TP), routes to the L2TP handler.
// Otherwise, writes to TUN.
func (e *Engine) handleInnerUDP(udpData []byte, remoteAddr *net.UDPAddr, spi uint32) {
	// UDP header: src_port(2) + dst_port(2) + length(2) + checksum(2) = 8 bytes minimum.
	if len(udpData) < 8 {
		log.Debug("inner UDP packet too short",
			"size", len(udpData),
			"from", remoteAddr,
		)
		return
	}

	dstPort := binary.BigEndian.Uint16(udpData[2:4])

	if dstPort == 1701 {
		// L2TP packet — route to L2TP handler.
		e.mu.Lock()
		handler := e.l2tpHandler
		e.mu.Unlock()

		if handler != nil {
			// Strip UDP header (8 bytes), pass L2TP payload.
			l2tpPayload := udpData[8:]
			handler.HandlePacket(l2tpPayload, remoteAddr)
		} else {
			log.Debug("L2TP packet received but no handler registered",
				"from", remoteAddr,
				"spi", fmt.Sprintf("0x%08X", spi),
			)
		}
		return
	}

	// Non-L2TP UDP — write the full UDP datagram to TUN.
	if e.tunWriter != nil {
		if err := e.tunWriter.WritePacket(udpData, len(udpData)); err != nil {
			log.Warn("TUN write failed for inner UDP",
				"spi", fmt.Sprintf("0x%08X", spi),
				"dst_port", dstPort,
				"error", err.Error(),
			)
		}
	}
}

// outboundLoop reads raw IP packets from TUN, encrypts via ESP,
// and sends over UDP to the peer.
func (e *Engine) outboundLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		buf := e.pool.Get()

		n, err := e.tunReader.ReadPacket(buf)
		if err != nil {
			e.pool.Put(buf)

			// Check if shutting down.
			select {
			case <-ctx.Done():
				return
			default:
			}

			log.Debug("TUN read error", "error", err.Error())
			continue
		}

		if n == 0 {
			e.pool.Put(buf)
			continue
		}

		// Determine next header and destination IP from IP version.
		nextHeader := detectIPVersion(buf[:n])
		dstIP := extractDstIP(buf[:n])

		// Get outbound SA from SPD, fallback to default.
		e.mu.Lock()
		var outSA *SecurityAssociation
		if dstIP != nil {
			outSA = e.spd[string(dstIP.To16())]
		}
		if outSA == nil {
			outSA = e.defaultOutSA
		}
		e.mu.Unlock()

		if outSA == nil {
			e.pool.Put(buf)
			log.Debug("no outbound SA configured, dropping packet", "size", n)
			continue
		}

		// Encrypt via ESP.
		espPacket, err := Encrypt(outSA, buf[:n], nextHeader)
		e.pool.Put(buf)

		if err != nil {
			log.Warn("ESP encrypt failed",
				"spi", fmt.Sprintf("0x%08X", outSA.SPI),
				"error", err.Error(),
			)

			continue
		}

		// Send encrypted ESP packet via UDP to peer.
		if e.udpSender != nil && outSA.PeerAddr != nil {
			if err := e.udpSender.SendTo(e.nattPort, espPacket, outSA.PeerAddr); err != nil {
				log.Warn("UDP send failed",
					"spi", fmt.Sprintf("0x%08X", outSA.SPI),
					"peer", outSA.PeerAddr,
					"error", err.Error(),
				)
			}
		}
	}
}

// detectIPVersion examines the first byte of a raw IP packet and returns
// the appropriate ESP NextHeader value.
func detectIPVersion(packet []byte) byte {
	if len(packet) == 0 {
		return NextHeaderIPv4
	}

	version := packet[0] >> 4
	switch version {
	case 4:
		return NextHeaderIPv4
	case 6:
		return NextHeaderIPv6
	default:
		return NextHeaderIPv4
	}
}

// extractDstIP parses the destination IP address from a raw IP packet.
func extractDstIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}

	version := packet[0] >> 4
	switch version {
	case 4:
		return net.IP(packet[16:20])

	case 6:
		if len(packet) < 40 {
			return nil
		}

		return net.IP(packet[24:40])

	}

	return nil
}
