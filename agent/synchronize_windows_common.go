//go:build windows

package agent

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/certkit-io/certkit-agent/utils"
)

func normalizeThumbprint(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, " ", "")
	return strings.ToUpper(value)
}

func certInStore(thumbprint string) (bool, error) {
	script := fmt.Sprintf(`
$thumb = '%s'
Test-Path ("Cert:\LocalMachine\My\" + $thumb)
`, escapePowerShellString(thumbprint))
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("certInStore", out)
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(out), "True"), nil
}

func importPfxToStore(pfxPath, password string) error {
	script := fmt.Sprintf(`
$pwd = ConvertTo-SecureString -String '%s' -AsPlainText -Force
Import-PfxCertificate -FilePath '%s' -CertStoreLocation 'Cert:\LocalMachine\My' -Password $pwd | Out-Null
`, escapePowerShellString(password), escapePowerShellString(pfxPath))
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("importPfxToStore", out)
	return err
}

func importPfxBytesToStore(pfxBytes []byte, password string) error {
	if len(pfxBytes) == 0 {
		return fmt.Errorf("missing PFX payload")
	}

	tempFile, err := os.CreateTemp("", "certkit-*.pfx")
	if err != nil {
		return fmt.Errorf("create temp pfx: %w", err)
	}
	tempPath := tempFile.Name()
	defer os.Remove(tempPath)

	if _, err := tempFile.Write(pfxBytes); err != nil {
		_ = tempFile.Close()
		return fmt.Errorf("write temp pfx: %w", err)
	}
	if err := tempFile.Close(); err != nil {
		return fmt.Errorf("close temp pfx: %w", err)
	}

	return importPfxToStore(tempPath, password)
}

func escapePowerShellString(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func logPowerShellOutput(name, output string) {
	output = strings.TrimSpace(output)
	if output == "" {
		return
	}
	log.Printf("PowerShell (%s): %s", name, output)
}
