package certman

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadCertFromPEM reads a PEM-encoded certificate from disk.
func LoadCertFromPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading cert file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM certificate in %q", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate %q: %w", path, err)
	}

	return cert, nil
}

// LoadKeyFromPEM reads a PEM-encoded ECDSA private key from disk.
func LoadKeyFromPEM(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM key in %q", path)
	}

	// Try PKCS8 first (modern format), then EC format.
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing PKCS8 key %q: %w", path, err)
		}

		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key in %q is not ECDSA", path)
		}

		return ecKey, nil

	case "EC PRIVATE KEY":
		ecKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing EC key %q: %w", path, err)
		}
		return ecKey, nil

	default:
		return nil, fmt.Errorf("unsupported PEM type %q in %q", block.Type, path)
	}
}

// SaveCertPEM writes a DER-encoded certificate as PEM to disk.
func SaveCertPEM(certDER []byte, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("creating cert file %q: %w", path, err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

// SaveKeyPEM writes an ECDSA private key as PEM (PKCS8 format) to disk.
// Key file is created with restricted permissions (0600).
func SaveKeyPEM(key *ecdsa.PrivateKey, path string) error {
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling private key: %w", err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating key file %q: %w", path, err)
	}
	defer f.Close()

	return pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	})
}

// ReadRawPEM reads a PEM file and returns the raw bytes (for embedding in profiles).
func ReadRawPEM(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading PEM file %q: %w", path, err)
	}

	return data, nil
}

// ReadDER reads a PEM file and returns the DER-encoded bytes.
func ReadDER(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file %q: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %q", path)
	}

	return block.Bytes, nil
}
