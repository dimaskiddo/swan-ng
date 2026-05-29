package certman

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// sswanProfile represents the strongSwan Android app profile format.
type sswanProfile struct {
	UUID   string      `json:"uuid"`
	Name   string      `json:"name"`
	Type   string      `json:"type"`
	Remote sswanRemote `json:"remote"`
	Local  sswanLocal  `json:"local"`
}

type sswanRemote struct {
	Addr string `json:"addr"`
	ID   string `json:"id"`
	Cert string `json:"cert"`
}

type sswanLocal struct {
	P12 string `json:"p12"`
	ID  string `json:"id"`
}

// ExportSSwan generates a strongSwan Android app profile (.sswan) as JSON.
// The profile contains the CA certificate and client P12 bundle as base64-encoded data.
func ExportSSwan(username, hostname, caCertPath, p12Path, outputPath string) error {
	log.Info("exporting Android .sswan profile", "username", username, "output", outputPath)

	// Read CA cert PEM for embedding.
	caPEM, err := ReadRawPEM(caCertPath)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}

	// Read P12 binary data.
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return fmt.Errorf("reading P12 file: %w", err)
	}

	profile := sswanProfile{
		UUID: uuid.New().String(),
		Name: fmt.Sprintf("SWAN-NG VPN (%s)", username),
		Type: "ikev2-cert",
		Remote: sswanRemote{
			Addr: hostname,
			ID:   hostname,
			Cert: base64.StdEncoding.EncodeToString(caPEM),
		},
		Local: sswanLocal{
			P12: base64.StdEncoding.EncodeToString(p12Data),
			ID:  username,
		},
	}

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling .sswan profile: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("writing .sswan file: %w", err)
	}

	log.Info("Android .sswan profile exported", "path", outputPath)
	return nil
}
