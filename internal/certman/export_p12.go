package certman

import (
	"crypto/x509"
	"fmt"
	"os"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// ExportP12 creates a PKCS#12 (.p12) bundle containing the client certificate,
// private key, and CA certificate chain. The bundle is password-protected.
// Uses software.sslmate.com/src/go-pkcs12 for encoding (pure Go, no CGO).
func ExportP12(clientCertPath, clientKeyPath, caCertPath, outputPath, password string) error {
	log.Info("exporting PKCS#12 bundle", "output", outputPath)

	clientCert, err := LoadCertFromPEM(clientCertPath)
	if err != nil {
		return fmt.Errorf("loading client cert for P12: %w", err)
	}

	clientKey, err := LoadKeyFromPEM(clientKeyPath)
	if err != nil {
		return fmt.Errorf("loading client key for P12: %w", err)
	}

	caCert, err := LoadCertFromPEM(caCertPath)
	if err != nil {
		return fmt.Errorf("loading CA cert for P12: %w", err)
	}

	// Encode PKCS#12 with client cert, key, and CA cert chain.
	pfxData, err := gopkcs12.Modern.Encode(clientKey, clientCert, []*x509.Certificate{caCert}, password)
	if err != nil {
		return fmt.Errorf("encoding PKCS#12: %w", err)
	}

	if err := os.WriteFile(outputPath, pfxData, 0600); err != nil {
		return fmt.Errorf("writing P12 file: %w", err)
	}

	log.Info("PKCS#12 bundle exported", "path", outputPath)
	return nil
}
