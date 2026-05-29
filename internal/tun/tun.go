package tun

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"sync"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

const (
	// DefaultDeviceName is the default TUN device name on Linux.
	DefaultDeviceName = "swan0"

	// DefaultMTU is the default MTU for the TUN interface.
	// 1280 is the IPv6 minimum MTU and provides headroom for ESP overhead.
	DefaultMTU = 1280

	// MaxPacketSize is the maximum buffer size for reading from TUN.
	MaxPacketSize = 65536

	// tunReadOffset is the offset in the buffer for TUN read operations.
	// wireguard/tun on some platforms prepends a 4-byte header (PI header).
	tunReadOffset = 4
)

// Device wraps a platform-specific TUN device for reading/writing
// raw IP packets in user-space. Thread-safe for concurrent read/write.
type Device struct {
	name   string
	mtu    int
	dev    tunDevice // platform-specific interface
	mu     sync.Mutex
	closed bool
}

// tunDevice is the interface satisfied by the platform TUN implementation.
// It mirrors the subset of tun.Device we use from golang.zx2c4.com/wireguard/tun.
type tunDevice interface {
	// Read reads one or more packets from the TUN device.
	// bufs is a set of buffers to read into.
	// sizes will be set to the size of each packet read.
	// offset is the offset within each buffer to begin reading.
	Read(bufs [][]byte, sizes []int, offset int) (n int, err error)

	// Write writes one or more packets to the TUN device.
	// bufs is a set of buffers to write.
	// offset is the offset within each buffer where the packet begins.
	Write(bufs [][]byte, offset int) (int, error)

	// Close closes the TUN device.
	Close() error

	// Name returns the name of the TUN device.
	Name() (string, error)

	// MTU returns the MTU of the TUN device.
	MTU() (int, error)
}

// NewDevice creates a TUN device with the given name and MTU.
// The device name convention follows platform standards:
//   - Linux: swan0, swan1, swanN
//   - macOS: utun (auto-assigned by kernel)
//   - Windows: adapter name visible in Network Connections
//
// Returns error if the platform does not support TUN creation or
// if required privileges are missing (typically needs root/admin).
func NewDevice(ctx context.Context, name string, mtu int) (*Device, error) {
	if name == "" {
		name = DefaultDeviceName
	}

	if mtu <= 0 {
		mtu = DefaultMTU
	}

	log.Info("creating TUN device",
		"requested_name", name,
		"mtu", mtu,
		"os", runtime.GOOS,
	)

	dev, actualName, err := createPlatformTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("creating TUN device %q: %w", name, err)
	}

	d := &Device{
		name: actualName,
		mtu:  mtu,
		dev:  dev,
	}

	log.Info("TUN device created",
		"name", actualName,
		"mtu", mtu,
	)

	// Start shutdown watcher.
	go d.watchContext(ctx)

	return d, nil
}

// Name returns the actual name of the TUN device.
func (d *Device) Name() string {
	return d.name
}

// MTU returns the configured MTU.
func (d *Device) MTU() int {
	return d.mtu
}

// ReadPacket reads a single raw IP packet from the TUN device into buf.
// Returns the number of bytes read (starting at buf[0]).
// Caller must provide a buffer of at least MaxPacketSize bytes.
//
// This method blocks until a packet is available or the device is closed.
// On close, returns an error.
func (d *Device) ReadPacket(buf []byte) (int, error) {
	if len(buf) < tunReadOffset+1 {
		return 0, fmt.Errorf("buffer too small for TUN read: need >= %d, got %d", tunReadOffset+1, len(buf))
	}

	// wireguard/tun batch API: read into a single-element slice.
	bufs := [][]byte{buf}
	sizes := make([]int, 1)

	n, err := d.dev.Read(bufs, sizes, tunReadOffset)
	if err != nil {
		return 0, fmt.Errorf("TUN read: %w", err)
	}

	if n == 0 {
		return 0, fmt.Errorf("TUN read returned 0 packets")
	}

	// Copy packet data from offset position to start of buffer.
	pktSize := sizes[0]
	if pktSize > 0 && tunReadOffset > 0 {
		copy(buf[:pktSize], buf[tunReadOffset:tunReadOffset+pktSize])
	}

	return pktSize, nil
}

// WritePacket writes a raw IP packet to the TUN device.
// The packet should start at buf[0] with length n.
func (d *Device) WritePacket(buf []byte, n int) error {
	if n <= 0 {
		return nil
	}

	// wireguard/tun batch API: write from a single-element slice.
	// We need to provide the packet at the correct offset.
	writeBuf := make([]byte, tunReadOffset+n)
	copy(writeBuf[tunReadOffset:], buf[:n])

	bufs := [][]byte{writeBuf}
	_, err := d.dev.Write(bufs, tunReadOffset)
	if err != nil {
		return fmt.Errorf("TUN write: %w", err)
	}

	return nil
}

// Close shuts down the TUN device and releases resources.
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true

	log.Info("closing TUN device", "name", d.name)

	if err := d.dev.Close(); err != nil {
		return fmt.Errorf("closing TUN device %q: %w", d.name, err)
	}

	return nil
}

// IsClosed returns whether the device has been closed.
func (d *Device) IsClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.closed
}

// watchContext monitors the context and closes the device when cancelled.
func (d *Device) watchContext(ctx context.Context) {
	<-ctx.Done()
	if err := d.Close(); err != nil {
		// Only log if the error is not due to the device already being closed.
		if !d.IsClosed() {
			log.Error("error closing TUN device on context cancel",
				"name", d.name,
				"error", err.Error(),
			)
		}
	}
}

// Available reports whether TUN device creation is likely to succeed
// on the current platform and environment. Returns false with a reason
// if creation would fail (e.g., not root, missing kernel module).
func Available() (bool, string) {
	switch runtime.GOOS {
	case "linux":
		// Check for /dev/net/tun.
		if _, err := os.Stat("/dev/net/tun"); err != nil {
			return false, "TUN device node /dev/net/tun not found (try: modprobe tun)"
		}

		// Check for root (UID 0) or CAP_NET_ADMIN.
		if os.Geteuid() != 0 {
			return false, "TUN creation requires root privileges or CAP_NET_ADMIN"
		}

		return true, ""

	case "darwin":
		// macOS always has utun support, but needs root.
		if os.Geteuid() != 0 {
			return false, "TUN creation requires root privileges on macOS"
		}

		return true, ""

	case "windows":
		// Wintun driver must be installed. We can't easily check here.
		return true, ""

	default:
		return false, fmt.Sprintf("unsupported platform: %s", runtime.GOOS)
	}
}
