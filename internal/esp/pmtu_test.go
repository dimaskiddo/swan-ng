package esp

import (
	"net"
	"testing"
)

func TestPMTUManager_DefaultMTU(t *testing.T) {
	m := NewPMTUManager(DefaultMTU)

	peer := net.ParseIP("10.0.0.1")
	mtu := m.GetMTU(peer)
	if mtu != DefaultMTU {
		t.Errorf("expected default MTU %d, got %d", DefaultMTU, mtu)
	}
}

func TestPMTUManager_SetAndGet(t *testing.T) {
	m := NewPMTUManager(DefaultMTU)

	peer := net.ParseIP("10.0.0.1")
	m.SetMTU(peer, 1280)

	mtu := m.GetMTU(peer)
	if mtu != 1280 {
		t.Errorf("expected MTU 1280, got %d", mtu)
	}

	// Different peer should get default.
	other := net.ParseIP("10.0.0.2")
	mtu = m.GetMTU(other)
	if mtu != DefaultMTU {
		t.Errorf("expected default MTU %d for other peer, got %d", DefaultMTU, mtu)
	}
}

func TestPMTUManager_MinMTU(t *testing.T) {
	m := NewPMTUManager(DefaultMTU)

	peer := net.ParseIP("10.0.0.1")
	m.SetMTU(peer, 100) // Below MinMTU

	mtu := m.GetMTU(peer)
	if mtu != MinMTU {
		t.Errorf("expected MinMTU %d, got %d", MinMTU, mtu)
	}
}

func TestPMTUManager_InvalidDefaultMTU(t *testing.T) {
	m := NewPMTUManager(0) // Below MinMTU

	if m.DefaultMTUValue() != DefaultMTU {
		t.Errorf("expected default MTU %d for invalid input, got %d", DefaultMTU, m.DefaultMTUValue())
	}
}

func TestCalculateESPOverhead_AEAD(t *testing.T) {
	overhead := CalculateESPOverhead(AES256GCM, IntegNone, false)

	// ESP header(8) + IV(8) + tag(16) + max_pad+trailer(4+2=6) = 38
	expected := 38
	if overhead != expected {
		t.Errorf("AES-256-GCM overhead: expected %d, got %d", expected, overhead)
	}
}

func TestCalculateESPOverhead_CBC(t *testing.T) {
	overhead := CalculateESPOverhead(AES128CBC, IntegHMAC_SHA1_96, false)

	// ESP header(8) + IV(16) + block(16) + trailer(2) + ICV(12) = 54
	if overhead != 54 {
		t.Errorf("AES-128-CBC+SHA1 overhead: expected 54, got %d", overhead)
	}
}

func TestCalculateESPOverhead_NATTEncap(t *testing.T) {
	withoutNATT := CalculateESPOverhead(AES256GCM, IntegNone, false)
	withNATT := CalculateESPOverhead(AES256GCM, IntegNone, true)

	if withNATT != withoutNATT+28 {
		t.Errorf("NAT-T should add 28 bytes: without=%d, with=%d", withoutNATT, withNATT)
	}
}

func TestBuildICMPFragNeeded(t *testing.T) {
	// Build a minimal IPv4 packet (20 bytes header + 8 bytes payload).
	origPacket := make([]byte, 28)
	origPacket[0] = 0x45 // IPv4, IHL=5
	origPacket[12] = 10  // src: 10.0.0.1
	origPacket[13] = 0
	origPacket[14] = 0
	origPacket[15] = 1
	origPacket[16] = 192 // dst: 192.168.1.1
	origPacket[17] = 168
	origPacket[18] = 1
	origPacket[19] = 1

	result := BuildICMPFragNeeded(origPacket, 1400)

	// Result should be an IPv4 packet: 20 (IP) + 8 (ICMP header) + 28 (orig data) = 56.
	if len(result) != 56 {
		t.Errorf("expected ICMP packet length 56, got %d", len(result))
	}

	// Check IPv4 header.
	if result[0] != 0x45 {
		t.Errorf("expected IPv4 version/IHL 0x45, got 0x%02X", result[0])
	}

	// Protocol should be ICMP (1).
	if result[9] != 1 {
		t.Errorf("expected protocol ICMP (1), got %d", result[9])
	}

	// Source should be original destination (192.168.1.1).
	if result[12] != 192 || result[13] != 168 || result[14] != 1 || result[15] != 1 {
		t.Errorf("source IP mismatch")
	}

	// Destination should be original source (10.0.0.1).
	if result[16] != 10 || result[17] != 0 || result[18] != 0 || result[19] != 1 {
		t.Errorf("destination IP mismatch")
	}

	// ICMP Type=3, Code=4.
	if result[20] != 3 {
		t.Errorf("expected ICMP type 3, got %d", result[20])
	}

	if result[21] != 4 {
		t.Errorf("expected ICMP code 4, got %d", result[21])
	}
}

func TestCheckPacketExceedsMTU(t *testing.T) {
	exceeds, innerMTU := CheckPacketExceedsMTU(1400, 1500, 58)
	if exceeds {
		t.Errorf("1400 should fit in MTU 1500 - 58 = %d", innerMTU)
	}

	exceeds, innerMTU = CheckPacketExceedsMTU(1500, 1500, 58)
	if !exceeds {
		t.Errorf("1500 should exceed MTU 1500 - 58 = %d", innerMTU)
	}
}

func TestHasDFBit(t *testing.T) {
	// No DF bit.
	pkt := make([]byte, 20)
	pkt[0] = 0x45
	if HasDFBit(pkt) {
		t.Error("expected no DF bit")
	}

	// Set DF bit.
	pkt[6] = 0x40
	if !HasDFBit(pkt) {
		t.Error("expected DF bit set")
	}
}

func TestInnerMTUFromPath(t *testing.T) {
	mtu := InnerMTUFromPath(1500, 58)
	if mtu != 1442 {
		t.Errorf("expected 1442, got %d", mtu)
	}

	// Very small path MTU should clamp to MinMTU.
	mtu = InnerMTUFromPath(100, 58)
	if mtu != uint16(MinMTU) {
		t.Errorf("expected MinMTU %d, got %d", MinMTU, mtu)
	}
}
