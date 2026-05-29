package esp

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// Protocol numbers per IANA for NextHeader field (RFC 4303 §2.6).
const (
	NextHeaderIPv4  byte = 4  // Inner IPv4 packet (tunnel mode)
	NextHeaderUDP   byte = 17 // Inner UDP packet (transport mode, e.g. L2TP)
	NextHeaderIPv6  byte = 41 // Inner IPv6 packet (tunnel mode)
	NextHeaderDummy byte = 59 // Dummy packet for TFC (discard)
)

// ESPHeader represents the fixed 8-byte ESP header per RFC 4303 §2.
type ESPHeader struct {
	SPI    uint32 // Security Parameters Index
	SeqNum uint32 // 32-bit sequence number (low-order bits)
}

// ParseHeader extracts the ESP header from the first 8 bytes of a packet.
// Returns error if buffer is too short.
func ParseHeader(buf []byte) (ESPHeader, error) {
	if len(buf) < ESPHeaderLen {
		return ESPHeader{}, fmt.Errorf("buffer too short for ESP header: need %d, got %d",
			ESPHeaderLen, len(buf))
	}

	return ESPHeader{
		SPI:    binary.BigEndian.Uint32(buf[0:4]),
		SeqNum: binary.BigEndian.Uint32(buf[4:8]),
	}, nil
}

// MarshalHeader writes the ESP header into the first 8 bytes of buf.
func MarshalHeader(buf []byte, hdr ESPHeader) {
	binary.BigEndian.PutUint32(buf[0:4], hdr.SPI)
	binary.BigEndian.PutUint32(buf[4:8], hdr.SeqNum)
}

// Encrypt constructs a complete ESP packet from an inner IP packet.
// Uses tunnel mode with combined AEAD (AES-GCM or ChaCha20-Poly1305).
//
// Wire format produced:
//
//	| SPI (4B) | SeqNum (4B) | IV (8B) | Encrypted[payload + padding + padLen + nextHdr] | AEAD Tag (16B) |
//
// The SPI and SeqNum are passed as additional authenticated data (AAD) to the AEAD cipher,
// ensuring their integrity per RFC 4303 §3.3.2.2.
func Encrypt(sa *SecurityAssociation, plainPayload []byte, nextHeader byte) ([]byte, error) {
	if sa == nil {
		return nil, fmt.Errorf("security association is nil")
	}

	if sa.AEAD == nil {
		return nil, fmt.Errorf("AEAD cipher not initialized for SPI 0x%08X", sa.SPI)
	}

	// Increment sequence number atomically (RFC 4303 §3.3.3).
	newSeq := atomic.AddUint64(&sa.SeqNum, 1)
	seqLow := uint32(newSeq & 0xFFFFFFFF)

	// Check for sequence number overflow (RFC 4303 §3.3.3).
	if newSeq > 0xFFFFFFFF && !sa.ESN {
		return nil, fmt.Errorf("sequence number overflow on SPI 0x%08X (anti-replay requires new SA)", sa.SPI)
	}

	// Build ESP trailer: padding + padLength + nextHeader (RFC 4303 §2.4, §2.5, §2.6).
	padded := buildESPTrailer(plainPayload, nextHeader)

	// Construct ESP header.
	hdr := ESPHeader{
		SPI:    sa.SPI,
		SeqNum: seqLow,
	}

	// Build explicit IV from sequence number.
	iv := SequenceToIV(newSeq)

	// Build 12-byte nonce: salt (4B) || IV (8B).
	nonce, err := BuildNonce(sa.Salt, iv)
	if err != nil {
		return nil, fmt.Errorf("building nonce for SPI 0x%08X: %w", sa.SPI, err)
	}

	// Construct AAD: SPI + SeqNum (8 bytes) per RFC 4303 §3.3.2.2.
	aad := make([]byte, ESPHeaderLen)
	MarshalHeader(aad, hdr)

	// AEAD Seal: encrypt and authenticate.
	ciphertext := sa.AEAD.Seal(nil, nonce, padded, aad)

	// Assemble final ESP packet: header (8B) + IV (8B) + ciphertext.
	espPacketLen := ESPHeaderLen + len(iv) + len(ciphertext)
	espPacket := make([]byte, espPacketLen)

	MarshalHeader(espPacket, hdr)
	copy(espPacket[ESPHeaderLen:], iv)
	copy(espPacket[ESPHeaderLen+len(iv):], ciphertext)

	return espPacket, nil
}

// Decrypt processes an incoming ESP packet: extracts the header, verifies
// anti-replay, decrypts the payload, and strips ESP trailer.
//
// Returns the inner IP packet and the NextHeader protocol number.
// On any failure (bad auth, replay, malformed), returns an error —
// the caller should silently drop the packet per AGENTS.md §12.
func Decrypt(sa *SecurityAssociation, espPacket []byte) ([]byte, byte, error) {
	if sa == nil {
		return nil, 0, fmt.Errorf("security association is nil")
	}

	if sa.AEAD == nil {
		return nil, 0, fmt.Errorf("AEAD cipher not initialized for SPI 0x%08X", sa.SPI)
	}

	ivSize := AEADIVSize(sa.CipherSuite)
	tagSize := sa.AEAD.Overhead()
	minPacketSize := ESPHeaderLen + ivSize + ESPTrailerMinLen + tagSize

	if len(espPacket) < minPacketSize {
		return nil, 0, fmt.Errorf("ESP packet too short: need >= %d, got %d", minPacketSize, len(espPacket))
	}

	// Parse header.
	hdr, err := ParseHeader(espPacket)
	if err != nil {
		return nil, 0, err
	}

	// Anti-replay check (RFC 4303 §3.4.3).
	// Use low 32-bit seq for now; ESN handling will use full 64-bit.
	seq64 := uint64(hdr.SeqNum)

	if sa.ReplayWindow != nil {
		if !sa.ReplayWindow.Check(seq64) {
			log.Debug("ESP anti-replay reject",
				"spi", fmt.Sprintf("0x%08X", hdr.SPI),
				"seq", hdr.SeqNum,
			)
			return nil, 0, fmt.Errorf("anti-replay check failed for SPI 0x%08X seq %d", hdr.SPI, hdr.SeqNum)
		}
	}

	// Extract IV from packet.
	iv := espPacket[ESPHeaderLen : ESPHeaderLen+ivSize]

	// Build nonce.
	nonce, err := BuildNonce(sa.Salt, iv)
	if err != nil {
		return nil, 0, fmt.Errorf("building nonce for SPI 0x%08X: %w", sa.SPI, err)
	}

	// Construct AAD: SPI + SeqNum (first 8 bytes of packet).
	aad := espPacket[:ESPHeaderLen]

	// Extract ciphertext (everything after header + IV).
	ciphertext := espPacket[ESPHeaderLen+ivSize:]

	// AEAD Open: decrypt and verify integrity.
	plaintext, err := sa.AEAD.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		log.Debug("ESP integrity check failed",
			"spi", fmt.Sprintf("0x%08X", hdr.SPI),
			"seq", hdr.SeqNum,
			"error", err.Error(),
		)

		return nil, 0, fmt.Errorf("AEAD authentication failed for SPI 0x%08X: %w", hdr.SPI, err)
	}

	// Integrity check passed — now update anti-replay window (RFC 4303 §3.4.3).
	if sa.ReplayWindow != nil {
		sa.ReplayWindow.Advance(seq64)
	}

	// Strip ESP trailer: extract PadLength and NextHeader from tail.
	innerPayload, nextHeader, err := stripESPTrailer(plaintext)
	if err != nil {
		return nil, 0, fmt.Errorf("stripping ESP trailer for SPI 0x%08X: %w", sa.SPI, err)
	}

	// Check for dummy packet (RFC 4303 §2.6).
	if nextHeader == NextHeaderDummy {
		log.Debug("ESP dummy packet discarded",
			"spi", fmt.Sprintf("0x%08X", hdr.SPI),
			"seq", hdr.SeqNum,
		)

		return nil, NextHeaderDummy, nil
	}

	return innerPayload, nextHeader, nil
}

// buildESPTrailer appends RFC 4303 §2.4/§2.5/§2.6 trailer to plaintext:
// padding bytes (1,2,3,...) + PadLength (1 byte) + NextHeader (1 byte).
//
// Padding ensures the total (payload + padding + padLen + nextHdr) is
// aligned to a 4-byte boundary per RFC 4303 §2.4.
func buildESPTrailer(payload []byte, nextHeader byte) []byte {
	// Total = payload + padding + 2 (padLen + nextHeader) must be multiple of 4.
	payloadLen := len(payload)
	totalWithoutPad := payloadLen + ESPTrailerMinLen
	remainder := totalWithoutPad % 4
	padLen := 0

	if remainder != 0 {
		padLen = 4 - remainder
	}

	result := make([]byte, payloadLen+padLen+ESPTrailerMinLen)
	copy(result, payload)

	// Fill padding with monotonically increasing bytes: 1, 2, 3, ... (RFC 4303 §2.4).
	for i := 0; i < padLen; i++ {
		result[payloadLen+i] = byte(i + 1)
	}

	// PadLength field.
	result[payloadLen+padLen] = byte(padLen)

	// NextHeader field.
	result[payloadLen+padLen+1] = nextHeader

	return result
}

// stripESPTrailer removes the ESP trailer from decrypted plaintext.
// Returns the inner payload and NextHeader value.
func stripESPTrailer(plaintext []byte) ([]byte, byte, error) {
	if len(plaintext) < ESPTrailerMinLen {
		return nil, 0, fmt.Errorf("plaintext too short to contain ESP trailer: %d bytes", len(plaintext))
	}

	nextHeader := plaintext[len(plaintext)-1]
	padLen := int(plaintext[len(plaintext)-2])

	trailerLen := padLen + ESPTrailerMinLen
	if trailerLen > len(plaintext) {
		return nil, 0, fmt.Errorf("invalid pad length %d exceeds plaintext length %d", padLen, len(plaintext))
	}

	// Validate padding bytes per default scheme (RFC 4303 §2.4): 1, 2, 3, ...
	padStart := len(plaintext) - ESPTrailerMinLen - padLen
	for i := 0; i < padLen; i++ {
		expected := byte(i + 1)
		actual := plaintext[padStart+i]

		if actual != expected {
			log.Debug("ESP padding validation warning",
				"index", i,
				"expected", expected,
				"actual", actual,
			)
			// RFC 4303 says receiver SHOULD inspect, but we don't reject — some
			// implementations use non-standard padding.
		}
	}

	return plaintext[:padStart], nextHeader, nil
}
