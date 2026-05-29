//go:build windows

package tun

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// createPlatformTUN creates a TUN device on Windows using wireguard/tun (Wintun driver).
// The requestedName is used as the adapter name shown in Network Connections.
// Requires the Wintun driver (wintun.dll) to be available.
func createPlatformTUN(requestedName string, mtu int) (tunDevice, string, error) {
	dev, err := wgtun.CreateTUN(requestedName, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("windows TUN creation failed for %q (mtu=%d): %w", requestedName, mtu, err)
	}

	actualName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", fmt.Errorf("getting TUN device name: %w", err)
	}

	return dev, actualName, nil
}
