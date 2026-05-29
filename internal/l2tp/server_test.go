package l2tp

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/ipam"
)

// mockTUNWriter captures packets written to TUN.
type mockTUNWriter struct {
	packets [][]byte
}

func (m *mockTUNWriter) WritePacket(buf []byte, n int) error {
	pkt := make([]byte, n)
	copy(pkt, buf[:n])
	m.packets = append(m.packets, pkt)
	return nil
}

// mockResponseSender captures L2TP responses sent to peers.
type mockResponseSender struct {
	responses []sentResponse
}

type sentResponse struct {
	data []byte
	addr *net.UDPAddr
}

func (m *mockResponseSender) SendL2TPResponse(data []byte, peerAddr *net.UDPAddr) error {
	resp := sentResponse{
		data: make([]byte, len(data)),
		addr: peerAddr,
	}
	copy(resp.data, data)
	m.responses = append(m.responses, resp)
	return nil
}

func newTestServer(t *testing.T) (*Server, *mockResponseSender, *mockTUNWriter) {
	t.Helper()

	pool, err := ipam.NewPool("192.168.42.2 - 192.168.42.254")
	if err != nil {
		t.Fatalf("pool creation failed: %v", err)
	}

	userDB := NewProfileUserDB()
	userDB.mu.Lock()
	userDB.users["testuser"] = "testpass"
	userDB.mu.Unlock()

	sender := &mockResponseSender{}
	tunW := &mockTUNWriter{}

	srv := NewServer(ServerConfig{
		Hostname:  "test-server",
		GatewayIP: net.IPv4(192, 168, 42, 1),
		DNS1:      net.IPv4(1, 1, 1, 1),
		DNS2:      net.IPv4(1, 0, 0, 1),
		Pool:      pool,
		UserDB:    userDB,
		Sender:    sender,
		TUNWriter: tunW,
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv.Start(ctx)

	return srv, sender, tunW
}

func peerAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4500}
}

func TestServer_HandleSCCRQ_CreatesNewTunnel(t *testing.T) {
	srv, sender, _ := newTestServer(t)

	// Build SCCRQ.
	avps := SerializeAVPs([]AVP{
		NewMessageTypeAVP(MsgSCCRQ),
		NewProtocolVersionAVP(),
		NewFramingCapAVP(),
		NewHostNameAVP("peer-lac"),
		NewAssignedTunnelIDAVP(100),
		NewReceiveWindowSizeAVP(4),
	})

	hdr := BuildControlHeader(0, 0, 0, 0, len(avps))
	pkt := make([]byte, len(hdr)+len(avps))
	copy(pkt, hdr)
	copy(pkt[len(hdr):], avps)

	srv.HandlePacket(pkt, peerAddr())

	// Should have at least one tunnel created.
	if srv.TunnelCount() != 1 {
		t.Errorf("TunnelCount: got %d, want 1", srv.TunnelCount())
	}

	// Should have sent responses (SCCRP + ZLB ACKs).
	if len(sender.responses) == 0 {
		t.Error("expected at least one response (SCCRP)")
	}

	// Verify first response contains SCCRP.
	for _, resp := range sender.responses {
		hdr, payload, err := ParseHeader(resp.data)
		if err != nil || !hdr.IsControl || len(payload) == 0 {
			continue
		}
		avps, err := ParseAVPs(payload)
		if err != nil {
			continue
		}
		msgType := GetMessageType(avps)
		if msgType == MsgSCCRP {
			// Verify SCCRP contains our assigned tunnel ID.
			tid, ok := GetAVPUint16(avps, AVPAssignedTunnelID)
			if !ok || tid == 0 {
				t.Error("SCCRP missing valid Assigned Tunnel ID")
			}

			// Verify hostname.
			hn, ok := GetAVPString(avps, AVPHostName)
			if !ok || hn != "test-server" {
				t.Errorf("SCCRP HostName: got %q, want %q", hn, "test-server")
			}
			return
		}
	}

	t.Error("did not find SCCRP in sent responses")
}

func TestServer_HandleInvalidPacket_NoError(t *testing.T) {
	srv, _, _ := newTestServer(t)

	// Too short — should be silently dropped, not panic.
	srv.HandlePacket([]byte{0x00}, peerAddr())

	// Bad version.
	buf := make([]byte, 12)
	buf[1] = 0x03 // version 3
	srv.HandlePacket(buf, peerAddr())

	// Should still be running with 0 tunnels.
	if srv.TunnelCount() != 0 {
		t.Errorf("TunnelCount: got %d, want 0", srv.TunnelCount())
	}
}

func TestServer_Close(t *testing.T) {
	srv, _, _ := newTestServer(t)

	// Create a tunnel first.
	avps := SerializeAVPs([]AVP{
		NewMessageTypeAVP(MsgSCCRQ),
		NewProtocolVersionAVP(),
		NewHostNameAVP("peer"),
		NewAssignedTunnelIDAVP(50),
	})
	hdr := BuildControlHeader(0, 0, 0, 0, len(avps))
	pkt := make([]byte, len(hdr)+len(avps))
	copy(pkt, hdr)
	copy(pkt[len(hdr):], avps)

	srv.HandlePacket(pkt, peerAddr())

	if srv.TunnelCount() == 0 {
		t.Fatal("expected at least 1 tunnel")
	}

	srv.Close()

	if srv.TunnelCount() != 0 {
		t.Errorf("after Close, TunnelCount: got %d, want 0", srv.TunnelCount())
	}
}

func TestControlChannel_SendAndReceive(t *testing.T) {
	var sent [][]byte
	cc := NewControlChannel(
		func(data []byte) {
			pkt := make([]byte, len(data))
			copy(pkt, data)
			sent = append(sent, pkt)
		},
		func() {},
	)

	// Send a message.
	cc.Send([]byte{0x01, 0x02, 0x03})

	if len(sent) != 1 {
		t.Fatalf("expected 1 sent message, got %d", len(sent))
	}
	if cc.SendNs() != 1 {
		t.Errorf("Ns after send: got %d, want 1", cc.SendNs())
	}
	if cc.PendingCount() != 1 {
		t.Errorf("PendingCount: got %d, want 1", cc.PendingCount())
	}

	// Acknowledge via Nr=1.
	inOrder := cc.Receive(0, 1, false)
	if !inOrder {
		t.Error("expected in-order")
	}
	if cc.PendingCount() != 0 {
		t.Errorf("PendingCount after ack: got %d, want 0", cc.PendingCount())
	}
}

func TestControlChannel_ZLB(t *testing.T) {
	var sent [][]byte
	cc := NewControlChannel(
		func(data []byte) {
			pkt := make([]byte, len(data))
			copy(pkt, data)
			sent = append(sent, pkt)
		},
		func() {},
	)

	cc.SendZLB()

	if len(sent) != 1 {
		t.Fatalf("expected 1 ZLB sent, got %d", len(sent))
	}

	// ZLB should not increment Ns.
	if cc.SendNs() != 0 {
		t.Errorf("Ns after ZLB: got %d, want 0", cc.SendNs())
	}
}

func TestControlChannel_DuplicateDetection(t *testing.T) {
	cc := NewControlChannel(func([]byte) {}, func() {})

	// First message Ns=0 — in-order.
	ok := cc.Receive(0, 0, false)
	if !ok {
		t.Error("first message should be in-order")
	}

	// Duplicate Ns=0 — should be rejected.
	ok = cc.Receive(0, 0, false)
	if ok {
		t.Error("duplicate should be rejected")
	}

	// Next Ns=1 — in-order.
	ok = cc.Receive(1, 0, false)
	if !ok {
		t.Error("Ns=1 should be in-order")
	}
}

func TestControlChannel_Retransmit(t *testing.T) {
	retransmitCount := 0
	cc := NewControlChannel(
		func(data []byte) {
			retransmitCount++
		},
		func() {},
	)

	// Send a message.
	cc.Send([]byte{0x01})
	initialCount := retransmitCount

	// Wait for retransmit timer to expire.
	time.Sleep(1200 * time.Millisecond)

	alive := cc.CheckRetransmit()
	if !alive {
		t.Error("tunnel should still be alive")
	}
	if retransmitCount <= initialCount {
		t.Error("expected retransmission")
	}
}

func TestProfileUserDB(t *testing.T) {
	db := NewProfileUserDB()

	// Manually add users.
	db.mu.Lock()
	db.users["alice"] = "pass123"
	db.users["bob"] = "secret"
	db.mu.Unlock()

	pw, found := db.LookupUser("alice")
	if !found || pw != "pass123" {
		t.Errorf("alice: found=%v, pw=%q", found, pw)
	}

	_, found = db.LookupUser("charlie")
	if found {
		t.Error("charlie should not exist")
	}

	if db.UserCount() != 2 {
		t.Errorf("UserCount: got %d, want 2", db.UserCount())
	}
}
