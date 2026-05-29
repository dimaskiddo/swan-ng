package certman

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCA(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")

	// First call should generate new CA.
	cert, key, err := InitCA(certsDir)
	if err != nil {
		t.Fatalf("InitCA (generate): %v", err)
	}
	if cert == nil || key == nil {
		t.Fatal("CA cert or key is nil")
	}
	if cert.Subject.CommonName != "SWAN-NG Root CA" {
		t.Errorf("CA CN = %q, want %q", cert.Subject.CommonName, "SWAN-NG Root CA")
	}
	if !cert.IsCA {
		t.Error("CA cert IsCA = false, want true")
	}

	// Verify files exist.
	if !fileExists(filepath.Join(certsDir, "ca.crt")) {
		t.Error("ca.crt not found")
	}
	if !fileExists(filepath.Join(certsDir, "ca.key")) {
		t.Error("ca.key not found")
	}

	// Second call should load existing CA (same serial).
	cert2, key2, err := InitCA(certsDir)
	if err != nil {
		t.Fatalf("InitCA (reload): %v", err)
	}
	if cert2.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("reloaded CA has different serial number")
	}
	if key2.D.Cmp(key.D) != 0 {
		t.Error("reloaded CA has different key")
	}
}

func TestInitServerCert(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")

	caCert, caKey, err := InitCA(certsDir)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	cert, _, err := InitServerCert(certsDir, "vpn.example.com", caCert, caKey)
	if err != nil {
		t.Fatalf("InitServerCert: %v", err)
	}
	if cert.Subject.CommonName != "vpn.example.com" {
		t.Errorf("server CN = %q, want %q", cert.Subject.CommonName, "vpn.example.com")
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != "vpn.example.com" {
		t.Error("server cert missing DNS SAN")
	}

	// Verify it's signed by our CA.
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("server cert not signed by CA: %v", err)
	}
}

func TestGenerateClientCert(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")

	caCert, caKey, err := InitCA(certsDir)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	// Need server cert to create clients dir.
	_, _, err = InitServerCert(certsDir, "vpn.example.com", caCert, caKey)
	if err != nil {
		t.Fatalf("InitServerCert: %v", err)
	}

	certPath, keyPath, err := GenerateClientCert(certsDir, "testuser", 120, caCert, caKey)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	// Verify files exist.
	if !fileExists(certPath) {
		t.Errorf("client cert not found at %s", certPath)
	}
	if !fileExists(keyPath) {
		t.Errorf("client key not found at %s", keyPath)
	}

	// Load and verify cert.
	clientCert, err := LoadCertFromPEM(certPath)
	if err != nil {
		t.Fatalf("loading client cert: %v", err)
	}
	if clientCert.Subject.CommonName != "testuser" {
		t.Errorf("client CN = %q, want %q", clientCert.Subject.CommonName, "testuser")
	}
	if err := clientCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("client cert not signed by CA: %v", err)
	}

	// Duplicate should fail.
	_, _, err = GenerateClientCert(certsDir, "testuser", 120, caCert, caKey)
	if err == nil {
		t.Error("expected error for duplicate client cert")
	}
}

func TestExportL2TPProfile(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "l2tp-test.txt")

	err := ExportL2TPProfile("testuser", "secret123", "vpn.example.com", "mypsk", outputPath)
	if err != nil {
		t.Fatalf("ExportL2TPProfile: %v", err)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("reading profile: %v", err)
	}

	content := string(data)
	checks := []string{
		"vpn.example.com",
		"testuser",
		"secret123",
		"mypsk",
		"L2TP over IPsec",
	}
	for _, check := range checks {
		if !strings.Contains(content, check) {
			t.Errorf("profile missing %q", check)
		}
	}
}

func TestExportSSwan(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")

	caCert, caKey, err := InitCA(certsDir)
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	_, _, err = InitServerCert(certsDir, "vpn.example.com", caCert, caKey)
	if err != nil {
		t.Fatalf("InitServerCert: %v", err)
	}

	certPath, keyPath, err := GenerateClientCert(certsDir, "sswanuser", 120, caCert, caKey)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	// Create P12 first.
	p12Path := filepath.Join(dir, "sswanuser.p12")
	caCertPath := filepath.Join(certsDir, "ca.crt")
	err = ExportP12(certPath, keyPath, caCertPath, p12Path, "test")
	if err != nil {
		t.Fatalf("ExportP12: %v", err)
	}

	// Export .sswan.
	sswanPath := filepath.Join(dir, "sswanuser.sswan")
	err = ExportSSwan("sswanuser", "vpn.example.com", caCertPath, p12Path, sswanPath)
	if err != nil {
		t.Fatalf("ExportSSwan: %v", err)
	}

	// Verify JSON structure.
	data, err := os.ReadFile(sswanPath)
	if err != nil {
		t.Fatalf("reading .sswan: %v", err)
	}

	var profile sswanProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("parsing .sswan JSON: %v", err)
	}
	if profile.Type != "ikev2-cert" {
		t.Errorf("type = %q, want %q", profile.Type, "ikev2-cert")
	}
	if profile.Remote.Addr != "vpn.example.com" {
		t.Errorf("remote.addr = %q, want %q", profile.Remote.Addr, "vpn.example.com")
	}
	if profile.Local.ID != "sswanuser" {
		t.Errorf("local.id = %q, want %q", profile.Local.ID, "sswanuser")
	}
}
