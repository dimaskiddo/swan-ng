package esp

import "fmt"

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
)

// ClassifyNATT determines whether a datagram received on UDP:4500
// is an IKE packet (Non-ESP Marker) or an ESP packet per RFC 3948 §3.
//
// Returns the packet type and the payload after stripping any markers.
func ClassifyNATT(buf []byte) (PacketType, []byte, error) {
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
		return 0, nil, fmt.Errorf("NAT-T ESP packet too short: need >= %d, got %d",
			MinNATTESPPacketLen, len(buf))
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
