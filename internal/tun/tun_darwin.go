//go:build darwin

package tun

import (
	"fmt"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// createPlatformTUN creates a TUN device on macOS using wireguard/tun.
// macOS uses utun devices which are auto-assigned by the kernel.
// The requestedName is used as a hint but macOS will assign a utunN name.
func createPlatformTUN(requestedName string, mtu int) (tunDevice, string, error) {
	// macOS utun devices are auto-numbered by the kernel.
	// We pass the requested name but the kernel may assign a different utunN.
	dev, err := wgtun.CreateTUN(requestedName, mtu)
	if err != nil {
		return nil, "", fmt.Errorf("darwin TUN creation failed (mtu=%d): %w", mtu, err)
	}

	actualName, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, "", fmt.Errorf("getting TUN device name: %w", err)
	}

	return dev, actualName, nil
}
