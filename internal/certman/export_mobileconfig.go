package certman

import (
	"encoding/base64"
	"fmt"
	"os"
	"text/template"

	"github.com/google/uuid"

	"github.com/dimaskiddo/swan-ng/internal/log"
)

// mobileconfigTemplate is the Apple Configuration Profile XML template for IKEv2 VPN.
const mobileconfigTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>ca.crt</string>
			<key>PayloadContent</key>
			<data>{{.CACertBase64}}</data>
			<key>PayloadDisplayName</key>
			<string>SWAN-NG Root CA</string>
			<key>PayloadIdentifier</key>
			<string>com.swan-ng.ca.{{.ProfileUUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>{{.CAUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
		<dict>
			<key>Password</key>
			<string>{{.P12Password}}</string>
			<key>PayloadCertificateFileName</key>
			<string>{{.Username}}.p12</string>
			<key>PayloadContent</key>
			<data>{{.P12Base64}}</data>
			<key>PayloadDisplayName</key>
			<string>{{.Username}} Client Certificate</string>
			<key>PayloadIdentifier</key>
			<string>com.swan-ng.client.{{.ProfileUUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.pkcs12</string>
			<key>PayloadUUID</key>
			<string>{{.ClientCertUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
		<dict>
			<key>PayloadDisplayName</key>
			<string>SWAN-NG VPN</string>
			<key>PayloadIdentifier</key>
			<string>com.swan-ng.vpn.{{.ProfileUUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.vpn.managed</string>
			<key>PayloadUUID</key>
			<string>{{.VPNUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>UserDefinedName</key>
			<string>SWAN-NG VPN ({{.Username}})</string>
			<key>VPNType</key>
			<string>IKEv2</string>
			<key>IKEv2</key>
			<dict>
				<key>AuthenticationMethod</key>
				<string>Certificate</string>
				<key>RemoteAddress</key>
				<string>{{.Hostname}}</string>
				<key>RemoteIdentifier</key>
				<string>{{.Hostname}}</string>
				<key>LocalIdentifier</key>
				<string>{{.Username}}</string>
				<key>PayloadCertificateUUID</key>
				<string>{{.ClientCertUUID}}</string>
				<key>CertificateType</key>
				<string>ECDSA384</string>
				<key>ServerCertificateIssuerCommonName</key>
				<string>SWAN-NG Root CA</string>
				<key>EnablePFS</key>
				<integer>1</integer>
				<key>IKESecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-384</string>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
				<key>ChildSecurityAssociationParameters</key>
				<dict>
					<key>EncryptionAlgorithm</key>
					<string>AES-256-GCM</string>
					<key>DiffieHellmanGroup</key>
					<integer>14</integer>
					<key>IntegrityAlgorithm</key>
					<string>SHA2-384</string>
					<key>LifeTimeInMinutes</key>
					<integer>1440</integer>
				</dict>
			</dict>
		</dict>
	</array>
	<key>PayloadDisplayName</key>
	<string>SWAN-NG VPN ({{.Username}})</string>
	<key>PayloadIdentifier</key>
	<string>com.swan-ng.profile.{{.Username}}</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{{.ProfileUUID}}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>`

// mobileconfigData holds template values for Apple .mobileconfig generation.
type mobileconfigData struct {
	Username       string
	Hostname       string
	CACertBase64   string
	P12Base64      string
	P12Password    string
	ProfileUUID    string
	CAUUID         string
	ClientCertUUID string
	VPNUUID        string
}

// ExportMobileconfig generates an Apple Configuration Profile (.mobileconfig)
// for IKEv2 VPN with certificate-based authentication.
func ExportMobileconfig(username, hostname, caCertPath, p12Path, p12Password, outputPath string) error {
	log.Info("exporting Apple .mobileconfig", "username", username, "output", outputPath)

	// Read CA cert DER for embedding.
	caDER, err := ReadDER(caCertPath)
	if err != nil {
		return fmt.Errorf("reading CA cert: %w", err)
	}

	// Read P12 binary data.
	p12Data, err := os.ReadFile(p12Path)
	if err != nil {
		return fmt.Errorf("reading P12 file: %w", err)
	}

	data := mobileconfigData{
		Username:       username,
		Hostname:       hostname,
		CACertBase64:   base64.StdEncoding.EncodeToString(caDER),
		P12Base64:      base64.StdEncoding.EncodeToString(p12Data),
		P12Password:    p12Password,
		ProfileUUID:    uuid.New().String(),
		CAUUID:         uuid.New().String(),
		ClientCertUUID: uuid.New().String(),
		VPNUUID:        uuid.New().String(),
	}

	tmpl, err := template.New("mobileconfig").Parse(mobileconfigTemplate)
	if err != nil {
		return fmt.Errorf("parsing mobileconfig template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("creating mobileconfig file: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("executing mobileconfig template: %w", err)
	}

	log.Info("Apple .mobileconfig exported", "path", outputPath)
	return nil
}
