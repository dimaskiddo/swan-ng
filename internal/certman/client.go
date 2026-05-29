package certman

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// GenerateClientCert creates a new client certificate signed by the CA.
// The certificate uses ECDSA P-384 and is valid for the specified number of months.
// Returns paths to the generated certificate and key files.
func GenerateClientCert(certsDir, username string, validityMonths int, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (certPath, keyPath string, err error) {
	clientsDir := filepath.Join(certsDir, "clients")

	certPath = filepath.Join(clientsDir, username+".crt")
	keyPath = filepath.Join(clientsDir, username+".key")

	// Check if client cert already exists.
	if fileExists(certPath) {
		return "", "", fmt.Errorf("client certificate already exists for %q at %s", username, certPath)
	}

	log.Info("generating client certificate",
		"username", username,
		"validity_months", validityMonths,
		"algorithm", "ECDSA P-384",
	)

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating client key: %w", err)
	}

	serialNumber, err := generateSerial()
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	notAfter := now.AddDate(0, validityMonths, 0)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   username,
			Organization: []string{"SWAN-NG"},
		},
		NotBefore: now,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("creating client certificate: %w", err)
	}

	if err := SaveCertPEM(certDER, certPath); err != nil {
		return "", "", fmt.Errorf("saving client cert: %w", err)
	}

	if err := SaveKeyPEM(key, keyPath); err != nil {
		return "", "", fmt.Errorf("saving client key: %w", err)
	}

	log.Info("client certificate generated",
		"username", username,
		"expires", notAfter.Format(time.RFC3339),
		"cert_path", certPath,
		"key_path", keyPath,
	)

	return certPath, keyPath, nil
}
