//go:build linux

package tun

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// createPlatformTUN creates a TUN device on Linux using wireguard/tun.
// On Linux, the requested device name (e.g., "swan0") is used directly.
// Returns the underlying device, actual assigned name, and any error.
func createPlatformTUN(requestedName string, mtu int) (tunDevice, string, error) {
	dev, err := wgtun.CreateTUN(requestedName, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("linux TUN creation failed for %q (mtu=%d): %w", requestedName, mtu, err)
	}

	actualName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", fmt.Errorf("getting TUN device name: %w", err)
	}

	return dev, actualName, nil
}
