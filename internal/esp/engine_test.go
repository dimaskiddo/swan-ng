package esp

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

// mockTUN implements TUNReader and TUNWriter using channels for testing.
type mockTUN struct {
	readCh  chan []byte // packets to be read from TUN
	writeCh chan []byte // packets written to TUN
	closed  bool
	mu      sync.Mutex
}

func newMockTUN() *mockTUN {
	return &mockTUN{
		readCh:  make(chan []byte, 100),
		writeCh: make(chan []byte, 100),
	}
}

func (m *mockTUN) ReadPacket(buf []byte) (int, error) {
	pkt, ok := <-m.readCh
	if !ok {
		return 0, fmt.Errorf("mock TUN closed")
	}

	n := copy(buf, pkt)
	return n, nil
}

func (m *mockTUN) WritePacket(buf []byte, n int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return fmt.Errorf("mock TUN closed")
	}

	pkt := make([]byte, n)
	copy(pkt, buf[:n])

	select {
	case m.writeCh <- pkt:
	default:
		return fmt.Errorf("mock TUN write channel full")
	}

	return nil
}

func (m *mockTUN) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.closed {
		m.closed = true
		close(m.readCh)
	}
}

// mockUDPSender captures outbound UDP sends for testing.
type mockUDPSender struct {
	mu      sync.Mutex
	sent    []sentPacket
	sendErr error
}

type sentPacket struct {
	port       int
	data       []byte
	remoteAddr *net.UDPAddr
}

func newMockUDPSender() *mockUDPSender {
	return &mockUDPSender{
		sent: make([]sentPacket, 0),
	}
}

func (m *mockUDPSender) SendTo(port int, data []byte, remoteAddr *net.UDPAddr) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.sendErr != nil {
		return m.sendErr
	}

	pkt := sentPacket{
		port:       port,
		data:       make([]byte, len(data)),
		remoteAddr: remoteAddr,
	}

	copy(pkt.data, data)
	m.sent = append(m.sent, pkt)

	return nil
}

func (m *mockUDPSender) getSent() []sentPacket {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := make([]sentPacket, len(m.sent))
	copy(result, m.sent)

	return result
}

func makeEngineTestSAPair(t *testing.T, suite CipherSuite, keySize int) (*SecurityAssociation, *SecurityAssociation) {
	t.Helper()

	key := make([]byte, keySize)
	salt := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}

	spiOut := uint32(0xEEEE0001)
	spiIn := uint32(0xEEEE0001)

	outSA, err := NewSecurityAssociation(spiOut, suite, key, salt, peer, false)
	if err != nil {
		t.Fatal(err)
	}

	inSA, err := NewSecurityAssociation(spiIn, suite, key, salt, &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4500}, true)
	if err != nil {
		t.Fatal(err)
	}

	return outSA, inSA
}

func TestEngineNewEngine(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)

	_, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
	})
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}
}

func TestEngineNewEngine_MissingDB(t *testing.T) {
	pool := NewBufferPool(MaxPacketSize)

	_, err := NewEngine(EngineConfig{
		Pool: pool,
	})
	if err == nil {
		t.Fatal("expected error for missing SADatabase")
	}
}

func TestEngineNewEngine_MissingPool(t *testing.T) {
	db := NewSADatabase()

	_, err := NewEngine(EngineConfig{
		SADatabase: db,
	})
	if err == nil {
		t.Fatal("expected error for missing Pool")
	}
}

func TestEngineInboundDecrypt(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)
	mockTun := newMockTUN()
	outSA, inSA := makeEngineTestSAPair(t, AES128GCM, 16)

	if err := db.AddInbound(inSA); err != nil {
		t.Fatal(err)
	}

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
		TUNWriter:  mockTun,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Create an ESP-encrypted packet simulating inbound traffic.
	// IPv4 test payload (version nibble = 4).
	payload := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
		0x0A, 0x00, 0x00, 0x02}

	espPacket, err := Encrypt(outSA, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}
	engine.HandleInboundESP(espPacket, len(espPacket), peer)

	// Check that decrypted packet arrived at mock TUN.
	select {
	case written := <-mockTun.writeCh:
		if !bytes.Equal(written, payload) {
			t.Fatalf("TUN write mismatch: got %x, want %x", written, payload)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for TUN write")
	}
}

func TestEngineInboundBadSPI(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)
	mockTun := newMockTUN()
	outSA, _ := makeEngineTestSAPair(t, AES128GCM, 16)

	// Do NOT add inSA to database — SPI lookup will fail.

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
		TUNWriter:  mockTun,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{0x45, 0x00, 0x00, 0x14}
	espPacket, err := Encrypt(outSA, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}
	engine.HandleInboundESP(espPacket, len(espPacket), peer)

	// Should be silently dropped — nothing in TUN write channel.
	select {
	case pkt := <-mockTun.writeCh:
		t.Fatalf("expected no TUN write, got %d bytes", len(pkt))
	case <-time.After(100 * time.Millisecond):
		// Expected: no write.
	}
}

func TestEngineInboundTampered(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)
	mockTun := newMockTUN()
	outSA, inSA := makeEngineTestSAPair(t, AES128GCM, 16)

	if err := db.AddInbound(inSA); err != nil {
		t.Fatal(err)
	}

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
		TUNWriter:  mockTun,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01}
	espPacket, err := Encrypt(outSA, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with ciphertext.
	espPacket[len(espPacket)-3] ^= 0xFF

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}
	engine.HandleInboundESP(espPacket, len(espPacket), peer)

	// Should be silently dropped.
	select {
	case pkt := <-mockTun.writeCh:
		t.Fatalf("tampered packet should be dropped, got %d bytes", len(pkt))
	case <-time.After(100 * time.Millisecond):
		// Expected.
	}
}

func TestEngineInboundTooShort(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
	})
	if err != nil {
		t.Fatal(err)
	}

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}

	// Packet shorter than ESP header — should be silently dropped.
	engine.HandleInboundESP([]byte{0x01, 0x02}, 2, peer)
}

func TestEngineOutboundEncrypt(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)
	mockTun := newMockTUN()
	mockUDP := newMockUDPSender()

	key := make([]byte, 16)
	salt := make([]byte, 4)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}
	outSA, err := NewSecurityAssociation(0xFFFF0001, AES128GCM, key, salt, peer, false)
	if err != nil {
		t.Fatal(err)
	}

	// Also create inbound SA with same crypto for verification.
	inSA, err := NewSecurityAssociation(0xFFFF0001, AES128GCM, key, salt, peer, true)
	if err != nil {
		t.Fatal(err)
	}

	engine, err := NewEngine(EngineConfig{
		SADatabase:        db,
		Pool:              pool,
		TUNReader:         mockTun,
		TUNWriter:         mockTun,
		UDPSender:         mockUDP,
		DefaultOutboundSA: outSA,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go engine.Start(ctx)

	// Give engine time to start.
	time.Sleep(50 * time.Millisecond)

	// Send an IPv4 packet into mock TUN for outbound processing.
	ipPacket := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
		0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
		0x0A, 0x00, 0x00, 0x02}

	mockTun.readCh <- ipPacket

	// Wait for outbound processing.
	time.Sleep(200 * time.Millisecond)

	cancel()
	mockTun.Close()
	time.Sleep(50 * time.Millisecond)

	// Verify ESP packet was sent via mock UDP.
	sent := mockUDP.getSent()
	if len(sent) == 0 {
		t.Fatal("expected at least 1 sent ESP packet")
	}

	// Verify the sent ESP packet can be decrypted.
	decrypted, nextHdr, err := Decrypt(inSA, sent[0].data)
	if err != nil {
		t.Fatalf("decrypt sent ESP packet failed: %v", err)
	}

	if nextHdr != NextHeaderIPv4 {
		t.Fatalf("expected NextHeader IPv4 (%d), got %d", NextHeaderIPv4, nextHdr)
	}

	if !bytes.Equal(decrypted, ipPacket) {
		t.Fatalf("decrypted payload mismatch")
	}

	if sent[0].port != 4500 {
		t.Fatalf("expected port 4500, got %d", sent[0].port)
	}

	if !sent[0].remoteAddr.IP.Equal(net.IPv4(10, 0, 0, 2)) {
		t.Fatalf("expected peer 10.0.0.2, got %s", sent[0].remoteAddr.IP)
	}
}

func TestEngineOutboundNoSA(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)
	mockTun := newMockTUN()
	mockUDP := newMockUDPSender()

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
		TUNReader:  mockTun,
		UDPSender:  mockUDP,
		// No DefaultOutboundSA — packets should be dropped.
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	go engine.Start(ctx)

	time.Sleep(50 * time.Millisecond)

	mockTun.readCh <- []byte{0x45, 0x00, 0x00, 0x14}

	time.Sleep(200 * time.Millisecond)

	cancel()
	mockTun.Close()
	time.Sleep(50 * time.Millisecond)

	sent := mockUDP.getSent()
	if len(sent) != 0 {
		t.Fatalf("expected 0 sent packets without outbound SA, got %d", len(sent))
	}
}

func TestEngineSetDefaultOutboundSA(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
	})
	if err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 16)
	salt := make([]byte, 4)
	rand.Read(key)
	rand.Read(salt)

	sa, err := NewSecurityAssociation(0xAAAA1111, AES128GCM, key, salt,
		&net.UDPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 4500}, false)
	if err != nil {
		t.Fatal(err)
	}

	engine.SetDefaultOutboundSA(sa)

	engine.mu.Lock()
	got := engine.defaultOutSA
	engine.mu.Unlock()

	if got == nil || got.SPI != 0xAAAA1111 {
		t.Fatal("default outbound SA not set correctly")
	}
}

func TestEngineInboundDummy(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)
	mockTun := newMockTUN()
	outSA, inSA := makeEngineTestSAPair(t, AES128GCM, 16)

	if err := db.AddInbound(inSA); err != nil {
		t.Fatal(err)
	}

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
		TUNWriter:  mockTun,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt a dummy packet (NextHeader=59).
	dummyPayload := make([]byte, 32)
	rand.Read(dummyPayload)

	espPacket, err := Encrypt(outSA, dummyPayload, NextHeaderDummy)
	if err != nil {
		t.Fatal(err)
	}

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}
	engine.HandleInboundESP(espPacket, len(espPacket), peer)

	// Dummy packets should be silently discarded — no TUN write.
	select {
	case pkt := <-mockTun.writeCh:
		t.Fatalf("dummy packet should not be written to TUN, got %d bytes", len(pkt))
	case <-time.After(100 * time.Millisecond):
		// Expected.
	}
}

func TestDetectIPVersion(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected byte
	}{
		{"IPv4", []byte{0x45, 0x00}, NextHeaderIPv4},
		{"IPv6", []byte{0x60, 0x00}, NextHeaderIPv6},
		{"empty", []byte{}, NextHeaderIPv4},
		{"unknown", []byte{0x30}, NextHeaderIPv4},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectIPVersion(tc.packet)
			if got != tc.expected {
				t.Fatalf("expected %d, got %d", tc.expected, got)
			}
		})
	}
}

func TestEngineInboundNATTIKE(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)
	mockTun := newMockTUN()

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
		TUNWriter:  mockTun,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Non-ESP Marker (4 zero bytes) + IKE data.
	ikePacket := append([]byte{0x00, 0x00, 0x00, 0x00}, []byte("ike-payload")...)
	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}

	engine.HandleInboundESP(ikePacket, len(ikePacket), peer)

	// IKE packets should not be written to TUN.
	select {
	case pkt := <-mockTun.writeCh:
		t.Fatalf("IKE packet should not be written to TUN, got %d bytes", len(pkt))
	case <-time.After(100 * time.Millisecond):
		// Expected.
	}
}

func TestEngineInboundReplay(t *testing.T) {
	db := NewSADatabase()
	pool := NewBufferPool(MaxPacketSize)
	mockTun := newMockTUN()
	outSA, inSA := makeEngineTestSAPair(t, AES128GCM, 16)

	if err := db.AddInbound(inSA); err != nil {
		t.Fatal(err)
	}

	engine, err := NewEngine(EngineConfig{
		SADatabase: db,
		Pool:       pool,
		TUNWriter:  mockTun,
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte{0x45, 0x00, 0x00, 0x14}
	espPacket, err := Encrypt(outSA, payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}

	peer := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 4500}

	// First time should succeed.
	engine.HandleInboundESP(espPacket, len(espPacket), peer)

	select {
	case <-mockTun.writeCh:
		// Good — first packet accepted.
	case <-time.After(1 * time.Second):
		t.Fatal("first packet should be accepted")
	}

	// Replay same packet — should be dropped.
	engine.HandleInboundESP(espPacket, len(espPacket), peer)

	select {
	case pkt := <-mockTun.writeCh:
		t.Fatalf("replayed packet should be dropped, got %d bytes", len(pkt))
	case <-time.After(100 * time.Millisecond):
		// Expected.
	}
}
