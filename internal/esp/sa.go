package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// SecurityAssociation holds the per-tunnel cryptographic state for an
// ESP Security Association. Looked up by SPI on inbound per RFC 4303 §2.1.
type SecurityAssociation struct {
	SPI          uint32              // Security Parameters Index
	SeqNum       uint64              // Outbound sequence counter (atomic)
	ESN          bool                // Extended Sequence Numbers enabled
	CipherSuite  CipherSuite         // Algorithm identifier
	AEAD         cipher.AEAD         // Initialized AEAD cipher (nil for CBC)
	CBCBlock     cipher.Block        // Initialized AES block cipher for CBC mode (nil for AEAD)
	Salt         []byte              // 4-byte salt for nonce construction (AEAD only)
	IntegSuite   IntegritySuite      // Integrity algorithm (IntegNone for AEAD)
	Integrity    *IntegrityAlgorithm // HMAC integrity instance (nil for AEAD)
	ReplayWindow *ReplayWindow       // Anti-replay window (inbound SAs)
	PeerAddr     *net.UDPAddr        // Remote endpoint
	TunnelMode   bool                // Always true for Phase 3
	CreatedAt    time.Time           // SA creation timestamp
}

// SADatabase is a thread-safe database of Security Associations.
// Inbound SAs are indexed by SPI for fast lookup.
type SADatabase struct {
	mu       sync.RWMutex
	bySPI    map[uint32]*SecurityAssociation // Inbound SA lookup by SPI
	outbound []*SecurityAssociation          // Outbound SAs
}

// NewSADatabase creates an empty SA database.
func NewSADatabase() *SADatabase {
	return &SADatabase{
		bySPI:    make(map[uint32]*SecurityAssociation),
		outbound: make([]*SecurityAssociation, 0),
	}
}

// GenerateSPI generates a random 32-bit SPI, avoiding the reserved range
// 0-255 per RFC 4303 §2.1.
func GenerateSPI() (uint32, error) {
	for {
		var buf [4]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, fmt.Errorf("generating random SPI: %w", err)
		}

		spi := binary.BigEndian.Uint32(buf[:])
		if spi > 255 {
			return spi, nil
		}

		// SPI in reserved range, retry.
	}
}

// AddInbound registers an inbound SA in the database, indexed by its SPI.
// Returns error if an SA with the same SPI already exists.
func (db *SADatabase) AddInbound(sa *SecurityAssociation) error {
	if sa == nil {
		return fmt.Errorf("cannot add nil security association")
	}

	if sa.SPI == 0 {
		return fmt.Errorf("SPI 0 is reserved for local use (RFC 4303 §2.1)")
	}

	if sa.SPI <= 255 {
		return fmt.Errorf("SPI %d is in IANA reserved range 1-255 (RFC 4303 §2.1)", sa.SPI)
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.bySPI[sa.SPI]; exists {
		return fmt.Errorf("inbound SA with SPI 0x%08X already exists", sa.SPI)
	}

	db.bySPI[sa.SPI] = sa

	log.Info("inbound SA added",
		"spi", fmt.Sprintf("0x%08X", sa.SPI),
		"cipher", sa.CipherSuite.String(),
		"peer", sa.PeerAddr,
	)

	return nil
}

// AddOutbound appends an outbound SA to the database.
func (db *SADatabase) AddOutbound(sa *SecurityAssociation) error {
	if sa == nil {
		return fmt.Errorf("cannot add nil security association")
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	db.outbound = append(db.outbound, sa)

	log.Info("outbound SA added",
		"spi", fmt.Sprintf("0x%08X", sa.SPI),
		"cipher", sa.CipherSuite.String(),
		"peer", sa.PeerAddr,
	)

	return nil
}

// LookupBySPI retrieves an inbound SA by its SPI.
// Returns nil if no matching SA is found (per RFC 4303 §3.4.2, discard packet).
func (db *SADatabase) LookupBySPI(spi uint32) *SecurityAssociation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.bySPI[spi]
}

// OutboundSAs returns a snapshot of all outbound SAs.
func (db *SADatabase) OutboundSAs() []*SecurityAssociation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]*SecurityAssociation, len(db.outbound))
	copy(result, db.outbound)

	return result
}

// RemoveInbound removes an inbound SA by SPI.
func (db *SADatabase) RemoveInbound(spi uint32) {
	db.mu.Lock()
	defer db.mu.Unlock()

	if _, exists := db.bySPI[spi]; exists {
		delete(db.bySPI, spi)

		log.Info("inbound SA removed", "spi", fmt.Sprintf("0x%08X", spi))
	}
}

// RemoveOutbound removes an outbound SA by SPI.
func (db *SADatabase) RemoveOutbound(spi uint32) {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, sa := range db.outbound {
		if sa.SPI == spi {
			db.outbound = append(db.outbound[:i], db.outbound[i+1:]...)

			log.Info("outbound SA removed", "spi", fmt.Sprintf("0x%08X", spi))
			return
		}
	}
}

// InboundCount returns the number of inbound SAs.
func (db *SADatabase) InboundCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return len(db.bySPI)
}

// OutboundCount returns the number of outbound SAs.
func (db *SADatabase) OutboundCount() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return len(db.outbound)
}

// NewSecurityAssociation creates a Security Association from negotiated IKE parameters.
func NewSecurityAssociation(spi uint32, suite CipherSuite, key []byte, salt []byte, peer *net.UDPAddr, withReplay bool) (*SecurityAssociation, error) {
	aead, err := NewAEAD(suite, key)
	if err != nil {
		return nil, fmt.Errorf("creating AEAD for test SA: %w", err)
	}

	sa := &SecurityAssociation{
		SPI:         spi,
		SeqNum:      0,
		ESN:         false,
		CipherSuite: suite,
		AEAD:        aead,
		Salt:        make([]byte, AEADSaltSize(suite)),
		IntegSuite:  IntegNone,
		PeerAddr:    peer,
		TunnelMode:  true,
		CreatedAt:   time.Now(),
	}

	copy(sa.Salt, salt)

	if withReplay {
		sa.ReplayWindow = NewReplayWindow(DefaultReplayWindowSize)
	}

	return sa, nil
}

// NewCBCSecurityAssociation creates a Security Association using AES-CBC
// with a separate HMAC integrity algorithm for legacy interoperability.
func NewCBCSecurityAssociation(spi uint32, suite CipherSuite, encrKey []byte, integSuite IntegritySuite, integKey []byte, peer *net.UDPAddr, withReplay bool) (*SecurityAssociation, error) {
	expectedKeySize := CipherKeySize(suite)
	if expectedKeySize == 0 {
		return nil, fmt.Errorf("unsupported CBC cipher suite: %s", suite)
	}

	if len(encrKey) != expectedKeySize {
		return nil, fmt.Errorf("invalid encryption key size for %s: expected %d, got %d",
			suite, expectedKeySize, len(encrKey))
	}

	block, err := aes.NewCipher(encrKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher for %s: %w", suite, err)
	}

	integ, err := NewIntegrity(integSuite, integKey)
	if err != nil {
		return nil, fmt.Errorf("creating integrity for %s: %w", integSuite, err)
	}

	sa := &SecurityAssociation{
		SPI:         spi,
		SeqNum:      0,
		ESN:         false,
		CipherSuite: suite,
		CBCBlock:    block,
		IntegSuite:  integSuite,
		Integrity:   integ,
		PeerAddr:    peer,
		TunnelMode:  true,
		CreatedAt:   time.Now(),
	}

	if withReplay {
		sa.ReplayWindow = NewReplayWindow(DefaultReplayWindowSize)
	}

	return sa, nil
}
