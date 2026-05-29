package certman

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

const (
	caValidityYears = 25
	caCertFile      = "ca.crt"
	caKeyFile       = "ca.key"
)

// InitCA initializes the Certificate Authority.
// If CA cert+key already exist in certsDir, they are loaded.
// If not, a new self-signed CA is generated with ECDSA P-384.
func InitCA(certsDir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, nil, fmt.Errorf("creating certs directory: %w", err)
	}

	certPath := filepath.Join(certsDir, caCertFile)
	keyPath := filepath.Join(certsDir, caKeyFile)

	if fileExists(certPath) && fileExists(keyPath) {
		log.Info("loading existing CA", "cert", certPath, "key", keyPath)

		cert, err := LoadCertFromPEM(certPath)
		if err != nil {
			return nil, nil, fmt.Errorf("loading CA cert: %w", err)
		}

		key, err := LoadKeyFromPEM(keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("loading CA key: %w", err)
		}

		log.Info("CA loaded",
			"subject", cert.Subject.CommonName,
			"expires", cert.NotAfter.Format(time.RFC3339),
		)

		return cert, key, nil
	}

	// Generate new CA.
	log.Info("generating new CA keypair", "algorithm", "ECDSA P-384")

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generating CA key: %w", err)
	}

	serialNumber, err := generateSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "SWAN-NG Root CA",
			Organization: []string{"SWAN-NG"},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(caValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creating CA certificate: %w", err)
	}

	if err := SaveCertPEM(certDER, certPath); err != nil {
		return nil, nil, fmt.Errorf("saving CA cert: %w", err)
	}

	if err := SaveKeyPEM(key, keyPath); err != nil {
		return nil, nil, fmt.Errorf("saving CA key: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing generated CA cert: %w", err)
	}

	log.Info("CA generated",
		"subject", cert.Subject.CommonName,
		"algorithm", "ECDSA P-384",
		"expires", cert.NotAfter.Format(time.RFC3339),
		"cert_path", certPath,
		"key_path", keyPath,
	)

	return cert, key, nil
}

// generateSerial creates a random 128-bit serial number for certificates.
func generateSerial() (*big.Int, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}

	return serial, nil
}

// fileExists checks if a file exists and is not a directory.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
