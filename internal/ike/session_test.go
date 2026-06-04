package ike

import (
	"net"
	"testing"

	"github.com/dimaskiddo/swan-ng/internal/esp"
)

func TestSessionManager_Isolation(t *testing.T) {
	pool := esp.NewBufferPool(1500)
	saDB := esp.NewSADatabase()
	espEngine, err := esp.NewEngine(esp.EngineConfig{
		SADatabase: saDB,
		Pool:       pool,
	})
	if err != nil {
		t.Fatalf("Failed to create ESP engine: %v", err)
	}
	sm := NewSessionManager(espEngine)

	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 500}

	// Create Session 1
	sess1 := &IKEv2Session{
		PeerAddr:   peerAddr,
		PeerIDType: IDIPv4Addr,
		PeerID:     []byte{192, 168, 1, 100},
	}
	copy(sess1.InitiatorSPI[:], []byte("initspi1"))
	copy(sess1.ResponderSPI[:], []byte("respspi1"))

	// Register Session 1
	sm.RegisterV2Session(sess1)

	// Verify Session 1 exists
	if sess := sm.GetV2Session(sess1.SPIPair()); sess == nil {
		t.Fatalf("Expected session 1 to be registered")
	}

	// Create Session 2 (same identity, different SPIs)
	sess2 := &IKEv2Session{
		PeerAddr:   peerAddr,
		PeerIDType: IDIPv4Addr,
		PeerID:     []byte{192, 168, 1, 100},
	}
	copy(sess2.InitiatorSPI[:], []byte("initspi2"))
	copy(sess2.ResponderSPI[:], []byte("respspi2"))

	// Register Session 2
	sm.RegisterV2Session(sess2)

	// Verify Session 2 exists
	if sess := sm.GetV2Session(sess2.SPIPair()); sess == nil {
		t.Fatalf("Expected session 2 to be registered")
	}

	// Verify Session 1 is evicted (Strict Isolation)
	if sess := sm.GetV2Session(sess1.SPIPair()); sess != nil {
		t.Fatalf("Expected session 1 to be evicted due to identity collision")
	}
}

func TestSessionManager_InstallChildSA(t *testing.T) {
	pool := esp.NewBufferPool(1500)
	saDB := esp.NewSADatabase()
	espEngine, err := esp.NewEngine(esp.EngineConfig{
		SADatabase: saDB,
		Pool:       pool,
	})
	if err != nil {
		t.Fatalf("Failed to create ESP engine: %v", err)
	}
	sm := NewSessionManager(espEngine)

	peerAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 4500}

	sess := &IKEv2Session{
		PeerAddr: peerAddr,
	}

	child := &IKEv2ChildSA{
		InSPI:       [4]byte{0x00, 0x00, 0x11, 0x11}, // 0x00001111
		OutSPI:      [4]byte{0x00, 0x00, 0x22, 0x22}, // 0x00002222
		EncrID:      20,                              // EncrAES_GCM_16
		EncrKey:     make([]byte, 20),                // 16 bytes key + 4 bytes salt
		PeerEncrKey: make([]byte, 20),
	}

	assignedIP := net.ParseIP("10.0.0.5")

	err = sm.InstallV2ChildSA(sess, child, assignedIP)
	if err != nil {
		t.Fatalf("InstallV2ChildSA failed: %v", err)
	}
}
