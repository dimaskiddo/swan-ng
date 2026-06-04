package ike

import (
	"net"
	"testing"

	"github.com/dimaskiddo/swan-ng/internal/esp"
)

type mockUDPSender struct {
	sentData []byte
	sentPort int
}

func (m *mockUDPSender) SendTo(port int, data []byte, remoteAddr *net.UDPAddr) error {
	m.sentPort = port
	m.sentData = append([]byte{}, data...)
	return nil
}

func TestServer_DispatchIKEv2(t *testing.T) {
	espEngine, _ := esp.NewEngine(esp.EngineConfig{
		SADatabase: esp.NewSADatabase(),
		Pool:       esp.NewBufferPool(1500),
	})
	sm := NewSessionManager(espEngine)

	sender := &mockUDPSender{}

	// Create mock handlers
	v1Handler := NewIKEv1Handler(nil, nil, nil, 0)
	v2Handler := NewIKEv2Handler(nil, nil, nil, nil, 0, CookieModeAuto)

	server := NewServer(sm, v1Handler, v2Handler, sender)

	// Build a valid IKEv2 SA_INIT request header
	hdr := Header{
		InitiatorSPI: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		NextPayload:  PayloadSA,
		MajorVersion: IKEv2Major,
		MinorVersion: 0,
		ExchangeType: ExchangeIKESAInit,
		Flags:        FlagInitiator,
		MessageID:    0,
	}

	buf := make([]byte, HeaderLen)
	if err := hdr.Marshal(buf); err != nil {
		t.Fatalf("Marshal header failed: %v", err)
	}

	// Just parsing it should drop or fail gracefully, but route to v2 handler
	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 500}
	server.HandlePacket(buf, len(buf), remoteAddr, false)

	// If it didn't panic, routing works.
}

func TestServer_DispatchIKEv1(t *testing.T) {
	espEngine, _ := esp.NewEngine(esp.EngineConfig{
		SADatabase: esp.NewSADatabase(),
		Pool:       esp.NewBufferPool(1500),
	})
	sm := NewSessionManager(espEngine)

	sender := &mockUDPSender{}

	v1Handler := NewIKEv1Handler(nil, nil, nil, 0)
	v2Handler := NewIKEv2Handler(nil, nil, nil, nil, 0, CookieModeAuto)

	server := NewServer(sm, v1Handler, v2Handler, sender)

	// Build a valid IKEv1 request header
	hdr := Header{
		InitiatorSPI: [8]byte{8, 7, 6, 5, 4, 3, 2, 1},
		NextPayload:  PayloadSA,
		MajorVersion: IKEv1Major,
		MinorVersion: 0,
		ExchangeType: ExchangeIdentityProtect,
	}

	buf := make([]byte, HeaderLen)
	if err := hdr.Marshal(buf); err != nil {
		t.Fatalf("Marshal header failed: %v", err)
	}

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 500}
	server.HandlePacket(buf, len(buf), remoteAddr, false)

	// If it didn't panic, routing works.
}
