//go:build windows

package agent

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func privateCaTrustStoreUnsupportedReason() string {
	return ""
}

func isRootCaTrusted(ca config.PrivateCAConfig) (bool, error) {
	thumbprint, err := rootCaThumbprint(ca.RootCAPEM)
	if err != nil {
		return false, err
	}

	script := fmt.Sprintf(`
$thumb = '%s'
Test-Path ("Cert:\LocalMachine\Root\" + $thumb)
`, escapePowerShellString(thumbprint))
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("isRootCaTrusted", out)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(out), "True"), nil
}

func installRootCa(ca config.PrivateCAConfig) error {
	tempFile, err := os.CreateTemp("", "certkit-*.crt")
	if err != nil {
		return fmt.Errorf("create temp crt: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	if _, err := tempFile.Write([]byte(ca.RootCAPEM)); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write temp crt: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temp crt: %w", err)
	}

	script := fmt.Sprintf(`
Import-Certificate -FilePath '%s' -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
`, escapePowerShellString(tempPath))
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("installRootCa", out)
	if err != nil {
		return fmt.Errorf("import root CA certificate: %w", err)
	}
	return nil
}

func rootCaThumbprint(rootCaPem string) (string, error) {
	block, _ := pem.Decode([]byte(rootCaPem))
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("no certificate block found in root CA PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse root CA certificate: %w", err)
	}
	sum := sha1.Sum(cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:])), nil
}
