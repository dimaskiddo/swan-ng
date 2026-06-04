package esp

import (
	"fmt"
	"net"
)

// NAT-T UDP Encapsulation per RFC 3948.
//
// On UDP port 4500, the receiver distinguishes between IKE and ESP packets
// by inspecting the first 4 bytes:
//   - All zeros (0x00000000) → Non-ESP Marker → IKE packet
//   - Non-zero → SPI field → ESP packet
//
// This module handles the demultiplexing for the port 4500 listener.

const (
	// NonESPMarkerLen is the size of the Non-ESP Marker per RFC 3948 §2.
	NonESPMarkerLen = 4

	// MinNATTESPPacketLen is the minimum valid NAT-T ESP packet:
	// SPI (4) + SeqNum (4) + at least some ciphertext.
	MinNATTESPPacketLen = ESPHeaderLen + 1
)

// PacketType identifies whether a UDP:4500 datagram is IKE or ESP.
type PacketType uint8

const (
	// PacketTypeESP indicates an ESP-encapsulated packet (SPI non-zero).
	PacketTypeESP PacketType = iota + 1

	// PacketTypeIKE indicates an IKE packet (Non-ESP Marker: 4 zero bytes).
	PacketTypeIKE

	// PacketTypeKeepalive indicates a NAT-T keepalive (single 0xFF byte, RFC 3948 §4).
	PacketTypeKeepalive
)

// ClassifyNATT determines whether a datagram received on UDP:4500
// is an IKE packet (Non-ESP Marker) or an ESP packet per RFC 3948 §3.
//
// Returns the packet type and the payload after stripping any markers.
func ClassifyNATT(buf []byte) (PacketType, []byte, error) {
	// Check for NAT-T keepalive: single 0xFF byte (RFC 3948 §4).
	if len(buf) == 1 && buf[0] == 0xFF {
		return PacketTypeKeepalive, nil, nil
	}

	if len(buf) < NonESPMarkerLen {
		return 0, nil, fmt.Errorf("NAT-T packet too short: %d bytes", len(buf))
	}

	// Check for Non-ESP Marker (4 zero bytes) per RFC 3948 §2.
	if buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0 {
		// IKE packet — strip the 4-byte marker.
		ikePayload := buf[NonESPMarkerLen:]
		return PacketTypeIKE, ikePayload, nil
	}

	// Non-zero first 4 bytes → ESP packet.
	// The first 4 bytes are the SPI, so the full buffer is the ESP packet.
	if len(buf) < MinNATTESPPacketLen {
		return 0, nil, fmt.Errorf("NAT-T ESP packet too short: need >= %d, got %d", MinNATTESPPacketLen, len(buf))
	}

	return PacketTypeESP, buf, nil
}

// PrependNonESPMarker prepends the 4-byte Non-ESP Marker to an IKE packet
// for sending over UDP:4500 per RFC 3948 §2.
func PrependNonESPMarker(ikePacket []byte) []byte {
	result := make([]byte, NonESPMarkerLen+len(ikePacket))

	// First 4 bytes are already zero (Non-ESP Marker).
	copy(result[NonESPMarkerLen:], ikePacket)

	return result
}

// NATTKeepalivePacket is the single-byte keepalive per RFC 3948 §4.
var NATTKeepalivePacket = []byte{0xFF}

// SendNATTKeepalive sends a NAT-T keepalive packet to maintain NAT bindings.
// Per RFC 3948 §4, this is a single 0xFF byte sent on UDP port 4500.
func SendNATTKeepalive(sender UDPSender, peerAddr *net.UDPAddr) error {
	if sender == nil || peerAddr == nil {
		return fmt.Errorf("NAT-T keepalive: sender or peer address is nil")
	}

	return sender.SendTo(4500, NATTKeepalivePacket, peerAddr)
}

// IsNATTKeepalive returns true if the buffer is a NAT-T keepalive packet
// (single 0xFF byte per RFC 3948 §4).
func IsNATTKeepalive(buf []byte) bool {
	return len(buf) == 1 && buf[0] == 0xFF
}
