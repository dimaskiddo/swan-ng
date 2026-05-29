package certman

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

const (
	serverValidityYears = 10
	serverCertFile      = "server.crt"
	serverKeyFile       = "server.key"
)

// InitServerCert generates or loads the server certificate.
// The server cert is signed by the CA and includes the hostname as SAN.
func InitServerCert(certsDir, hostname string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	certPath := filepath.Join(certsDir, serverCertFile)
	keyPath := filepath.Join(certsDir, serverKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		log.Info("loading existing server certificate", "cert", certPath)

		cert, err := LoadCertFromPEM(certPath)
		if err != nil {
			return nil, nil, fmt.Errorf("loading server cert: %w", err)
		}

		key, err := LoadKeyFromPEM(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("loading server key: %w", err)
		}

		return cert, key, nil
	}

	log.Info("generating server certificate",
		"hostname", hostname,
		"algorithm", "ECDSA P-384",
	)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating server key: %w", err)
	}

	serialNumber, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"SWAN-NG"},
		},
		NotBefore: now,
		NotAfter:  now.AddDate(serverValidityYears, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{hostname},
	}

	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("creating server certificate: %w", err)
	}

	if err := SaveCertPEM(certDER, certPath); err != nil {
		return nil, nil, fmt.Errorf("saving server cert: %w", err)
	}

	if err := SaveKeyPEM(key, keyPath); err != nil {
		return nil, nil, fmt.Errorf("saving server key: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing generated server cert: %w", err)
	}

	if err := os.MkdirAll(filepath.Join(certsDir, "clients"), 0755); err != nil {
		return nil, nil, fmt.Errorf("creating clients directory: %w", err)
	}

	log.Info("server certificate generated",
		"hostname", hostname,
		"expires", cert.NotAfter.Format(time.RFC3339),
		"cert_path", certPath,
	)

	return cert, key, nil
}
