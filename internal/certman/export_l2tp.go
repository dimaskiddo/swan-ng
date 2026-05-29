package certman

import (
	"fmt"
	"os"
	"text/template"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// l2tpProfileTemplate is the distribution profile for L2TP over IPsec.
// This .txt file is given to network engineers configuring hardware endpoints.
const l2tpProfileTemplate = `====================================
  SWAN-NG L2TP/IPsec VPN Profile
====================================

Server Address : {{.Hostname}}
L2TP Username  : {{.Username}}
L2TP Password  : {{.Password}}
IPsec PSK      : {{.PSK}}

------------------------------------
Connection Type: L2TP over IPsec
Authentication : PSK + PPP CHAP
------------------------------------

Notes:
- Use the Server Address above as the VPN server endpoint.
- Enter the IPsec PSK in the IPsec/IKE pre-shared key field.
- Enter the L2TP Username and Password for PPP authentication.
- This profile supports multiple concurrent sessions.
====================================
`

// l2tpProfileData holds template values for L2TP profile generation.
type l2tpProfileData struct {
	Hostname string
	Username string
	Password string
	PSK      string
}

// ExportL2TPProfile generates a structured .txt distribution profile
// containing connection credentials for L2TP over IPsec.
// The PSK is read from the ipsec: configuration block per PSK Isolation Rule.
func ExportL2TPProfile(username, password, hostname, psk, outputPath string) error {
	log.Info("exporting L2TP distribution profile", "username", username, "output", outputPath)

	data := l2tpProfileData{
		Hostname: hostname,
		Username: username,
		Password: password,
		PSK:      psk,
	}

	tmpl, err := template.New("l2tp").Parse(l2tpProfileTemplate)
	if err != nil {
		return fmt.Errorf("parsing L2TP profile template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating L2TP profile file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("executing L2TP profile template: %w", err)
	}

	log.Info("L2TP distribution profile exported", "path", outputPath)
	return nil
}
