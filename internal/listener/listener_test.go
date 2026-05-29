package listener

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/esp"
)

func TestManagerBindAndReceive(t *testing.T) {
	pool := esp.NewBufferPool(esp.MaxPacketSize)
	mgr := NewManager(pool)

	var receivedData []byte
	var receivedAddr *net.UDPAddr
	var mu sync.Mutex
	done := make(chan struct{})

	handler := func(buf []byte, n int, remoteAddr *net.UDPAddr) {
		mu.Lock()
		receivedData = make([]byte, n)
		copy(receivedData, buf[:n])
		receivedAddr = remoteAddr
		mu.Unlock()

		select {
		case done <- struct{}{}:
		default:
		}
	}

	// Bind to ephemeral port.
	err := mgr.AddUDP("127.0.0.1", 0, "test", handler)
	if err != nil {
		t.Fatalf("AddUDP failed: %v", err)
	}

	// Get actual bound address from the listener's connection.
	boundAddr := mgr.listeners[0].conn.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go mgr.Start(ctx)

	// Give listener time to start read loop.
	time.Sleep(100 * time.Millisecond)

	// Send test packet.
	testData := []byte("hello swan-ng")
	sendConn, err := net.DialUDP("udp", nil, boundAddr)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer sendConn.Close()

	if _, err := sendConn.Write(testData); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	// Wait for packet.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for packet")
	}

	mu.Lock()
	defer mu.Unlock()

	if string(receivedData) != "hello swan-ng" {
		t.Fatalf("data mismatch: got %q", receivedData)
	}

	if receivedAddr == nil {
		t.Fatal("remote address is nil")
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
}

func TestManagerShutdown(t *testing.T) {
	pool := esp.NewBufferPool(esp.MaxPacketSize)
	mgr := NewManager(pool)

	handler := func(buf []byte, n int, remoteAddr *net.UDPAddr) {}

	err := mgr.AddUDP("127.0.0.1", 0, "shutdown-test", handler)
	if err != nil {
		t.Fatalf("AddUDP failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	startDone := make(chan struct{})

	go func() {
		mgr.Start(ctx)
		close(startDone)
	}()

	time.Sleep(50 * time.Millisecond)

	// Cancel context — should trigger clean shutdown.
	cancel()

	select {
	case <-startDone:
		// Shutdown completed.
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown timed out")
	}
}

func TestManagerSendTo(t *testing.T) {
	pool := esp.NewBufferPool(esp.MaxPacketSize)
	mgr := NewManager(pool)

	handler := func(buf []byte, n int, remoteAddr *net.UDPAddr) {}

	err := mgr.AddUDP("127.0.0.1", 0, "send-test", handler)
	if err != nil {
		t.Fatalf("AddUDP failed: %v", err)
	}

	boundAddr := mgr.listeners[0].conn.LocalAddr().(*net.UDPAddr)

	// Open a receiver to catch our sent packet.
	receiver, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("receiver listen failed: %v", err)
	}
	defer receiver.Close()

	receiverAddr := receiver.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go mgr.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	testData := []byte("outbound test")
	err = mgr.SendTo(boundAddr.Port, testData, receiverAddr)
	if err != nil {
		t.Fatalf("SendTo failed: %v", err)
	}

	buf := make([]byte, 256)
	receiver.SetReadDeadline(time.Now().Add(2 * time.Second))

	n, _, err := receiver.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("receiver read failed: %v", err)
	}

	if string(buf[:n]) != "outbound test" {
		t.Fatalf("sent data mismatch: got %q", buf[:n])
	}

	cancel()
}

func TestManagerGetConn(t *testing.T) {
	pool := esp.NewBufferPool(esp.MaxPacketSize)
	mgr := NewManager(pool)

	handler := func(buf []byte, n int, remoteAddr *net.UDPAddr) {}

	err := mgr.AddUDP("127.0.0.1", 0, "getconn-test", handler)
	if err != nil {
		t.Fatalf("AddUDP failed: %v", err)
	}

	boundPort := mgr.listeners[0].conn.LocalAddr().(*net.UDPAddr).Port

	conn := mgr.GetConn(boundPort)
	if conn == nil {
		t.Fatal("GetConn returned nil for bound port")
	}

	conn2 := mgr.GetConn(99999)
	if conn2 != nil {
		t.Fatal("GetConn should return nil for unbound port")
	}

	mgr.closeAll()
}

func TestManagerMultipleListeners(t *testing.T) {
	pool := esp.NewBufferPool(esp.MaxPacketSize)
	mgr := NewManager(pool)

	handler := func(buf []byte, n int, remoteAddr *net.UDPAddr) {}

	for i := 0; i < 3; i++ {
		err := mgr.AddUDP("127.0.0.1", 0, "multi-test", handler)
		if err != nil {
			t.Fatalf("AddUDP %d failed: %v", i, err)
		}
	}

	if len(mgr.listeners) != 3 {
		t.Fatalf("expected 3 listeners, got %d", len(mgr.listeners))
	}

	mgr.closeAll()
}
