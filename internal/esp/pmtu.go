package esp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

// MinMTU is the minimum acceptable MTU per RFC 791 (IPv4) and RFC 8201 (IPv6).
const MinMTU = 576

// PMTUManager tracks path MTU for each peer endpoint.
// Thread-safe for concurrent access from ESP engine goroutines.
type PMTUManager struct {
	mu         sync.RWMutex
	defaultMTU int
	byPeer     map[string]int // key = IP.String()
}

// NewPMTUManager creates a PMTU manager with the given default MTU.
func NewPMTUManager(defaultMTU int) *PMTUManager {
	if defaultMTU < MinMTU {
		defaultMTU = DefaultMTU
	}

	return &PMTUManager{
		defaultMTU: defaultMTU,
		byPeer:     make(map[string]int),
	}
}

// GetMTU returns the path MTU for a specific peer.
// Returns the default MTU if no specific value is known.
func (m *PMTUManager) GetMTU(peerIP net.IP) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if mtu, ok := m.byPeer[peerIP.String()]; ok {
		return mtu
	}

	return m.defaultMTU
}

// SetMTU updates the path MTU for a specific peer.
// Enforces minimum MTU per RFC 791.
func (m *PMTUManager) SetMTU(peerIP net.IP, mtu int) {
	if mtu < MinMTU {
		mtu = MinMTU
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.byPeer[peerIP.String()] = mtu
}

// DefaultMTUValue returns the configured default MTU.
func (m *PMTUManager) DefaultMTUValue() int {
	return m.defaultMTU
}

// CalculateESPOverhead returns the total bytes added by ESP encapsulation
// for a given cipher configuration. This includes:
// - ESP header (8 bytes)
// - IV (variable: 8 for AEAD, 16 for CBC)
// - Maximum padding + trailer (blockSize + 2)
// - ICV/tag (variable)
// - NAT-T UDP encapsulation (28 bytes: 20 IP + 8 UDP)
func CalculateESPOverhead(suite CipherSuite, integSuite IntegritySuite, nattEncap bool) int {
	overhead := ESPHeaderLen // 8 bytes: SPI + SeqNum

	if IsAEAD(suite) {
		overhead += AEADIVSize(suite) // 8 bytes explicit IV
		overhead += 16                // AEAD tag (GCM/ChaCha20)
		overhead += 4 + 2             // Max padding (4-byte align) + padLen + nextHeader
	} else {
		overhead += CBCIVSize(suite)             // 16 bytes random IV
		overhead += CBCBlockSize(suite) + 2      // Max padding (block align) + padLen + nextHeader
		overhead += IntegrityICVSize(integSuite) // Truncated HMAC
	}

	if nattEncap {
		overhead += 28 // IP header (20) + UDP header (8) for NAT-T
	}

	return overhead
}

// BuildICMPFragNeeded constructs an ICMPv4 Destination Unreachable
// (Type 3, Code 4 - Fragmentation Needed and DF Set) message.
// Contains the next-hop MTU and the beginning of the offending IP packet.
//
// RFC 792 + RFC 1191: ICMP message format:
//
//	| Type(1)=3 | Code(1)=4 | Checksum(2) |
//	| unused(2) | Next-Hop MTU(2)          |
//	| Original IP Header + first 8 bytes   |
func BuildICMPFragNeeded(originalPacket []byte, nextHopMTU uint16) []byte {
	// Include at most the original IP header + 8 bytes of payload.
	// Per RFC 792, we should include the IP header and 64 bits of data.
	origLen := len(originalPacket)
	if origLen > 28 { // 20-byte IP header + 8 bytes data
		origLen = 28
	}

	// ICMP header: Type(1) + Code(1) + Checksum(2) + Unused(2) + NextHopMTU(2) = 8 bytes.
	icmpLen := 8 + origLen
	icmp := make([]byte, icmpLen)

	icmp[0] = 3 // Type: Destination Unreachable
	icmp[1] = 4 // Code: Fragmentation Needed
	// icmp[2:4] = checksum (computed below)
	// icmp[4:6] = unused (zero)
	binary.BigEndian.PutUint16(icmp[6:8], nextHopMTU)

	// Copy original packet data.
	copy(icmp[8:], originalPacket[:origLen])

	// Compute ICMP checksum.
	checksum := icmpChecksum(icmp)
	binary.BigEndian.PutUint16(icmp[2:4], checksum)

	// Wrap in minimal IPv4 header for injection into TUN.
	// We need a source IP (the tunnel endpoint) — use 0.0.0.0 as placeholder;
	// the caller should set appropriate source from the SA peer address.
	return buildIPv4ICMPPacket(originalPacket, icmp)
}

// buildIPv4ICMPPacket wraps an ICMP message in a minimal IPv4 header.
// Source = destination of the original packet (our tunnel endpoint).
// Destination = source of the original packet.
func buildIPv4ICMPPacket(originalPacket []byte, icmpPayload []byte) []byte {
	if len(originalPacket) < 20 {
		return icmpPayload // Can't extract addresses, return raw ICMP.
	}

	totalLen := 20 + len(icmpPayload) // IPv4 header + ICMP payload
	pkt := make([]byte, totalLen)

	// IPv4 header.
	pkt[0] = 0x45 // Version 4, IHL 5 (20 bytes)
	pkt[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	// pkt[4:6] = identification (0)
	// pkt[6:8] = flags/fragment (0)
	pkt[8] = 64 // TTL
	pkt[9] = 1  // Protocol: ICMP
	// pkt[10:12] = header checksum (computed below)

	// Source = original destination (our endpoint).
	copy(pkt[12:16], originalPacket[16:20])
	// Destination = original source.
	copy(pkt[16:20], originalPacket[12:16])

	// Copy ICMP payload.
	copy(pkt[20:], icmpPayload)

	// Compute IPv4 header checksum.
	ipChecksum := ipv4HeaderChecksum(pkt[:20])
	binary.BigEndian.PutUint16(pkt[10:12], ipChecksum)

	return pkt
}

// icmpChecksum computes the Internet checksum per RFC 1071.
func icmpChecksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// ipv4HeaderChecksum computes the IPv4 header checksum per RFC 791.
func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(header); i += 2 {
		// Skip the checksum field itself (bytes 10-11).
		if i == 10 {
			continue
		}

		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

// CheckPacketExceedsMTU checks if an inner packet would exceed the path MTU
// after ESP encapsulation. Returns true and the effective inner MTU if it exceeds.
func CheckPacketExceedsMTU(innerPacketLen int, pathMTU int, espOverhead int) (exceeds bool, innerMTU int) {
	maxInnerSize := pathMTU - espOverhead
	if maxInnerSize < 0 {
		maxInnerSize = 0
	}

	if innerPacketLen > maxInnerSize {
		return true, maxInnerSize
	}

	return false, maxInnerSize
}

// InnerMTUFromPath calculates the maximum inner packet size given path MTU and ESP overhead.
func InnerMTUFromPath(pathMTU int, espOverhead int) uint16 {
	innerMTU := pathMTU - espOverhead
	if innerMTU < MinMTU {
		innerMTU = MinMTU
	}

	if innerMTU > 65535 {
		innerMTU = 65535
	}

	return uint16(innerMTU)
}

// HasDFBit checks if the Don't Fragment bit is set in an IPv4 packet.
func HasDFBit(packet []byte) bool {
	if len(packet) < 7 {
		return false
	}

	// Flags are in byte 6, bits 5-7.
	// DF = bit 6 (0x40).
	return packet[6]&0x40 != 0
}

// String returns a human-readable description of the PMTU entry.
func (m *PMTUManager) String(peerIP net.IP) string {
	mtu := m.GetMTU(peerIP)
	return fmt.Sprintf("PMTU[%s]=%d", peerIP, mtu)
}
