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

func setCertFriendlyName(thumbprint, certificateId string) error {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for setting friendly name")
	}

	script := fmt.Sprintf(`
$thumb = '%s'
$certId = '%s'

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

try {
    $matches = $store.Certificates.Find([System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $thumb, $false)
    if ($matches.Count -gt 0) {
        $cert = $matches[0]
        $expDate = $cert.NotAfter.ToString("yyyy-MM-dd")
        $cert.FriendlyName = "CertKit $certId Expires $expDate"
        Write-Host "Set friendly name: CertKit $certId Expires $expDate"
    } else {
        Write-Host "Warning: certificate $thumb not found in store for friendly name update"
    }
} finally {
    $store.Close()
}
`, escapePowerShellString(thumbprint), escapePowerShellString(certificateId))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("setCertFriendlyName", out)
	return err
}

func cleanupOldCertKitCerts(certificateId string) error {
	if certificateId == "" {
		return fmt.Errorf("missing certificate id for cleanup")
	}

	script := fmt.Sprintf(`
$prefix = 'CertKit %s '

$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My","LocalMachine")
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

try {
    $certs = $store.Certificates | Where-Object { $_.FriendlyName -like "$prefix*" } |
        Sort-Object NotAfter -Descending

    if ($certs.Count -le 2) {
        Write-Host "Found $($certs.Count) CertKit cert(s) for %s, nothing to clean up."
        return
    }

    $toRemove = $certs | Select-Object -Skip 2
    foreach ($old in $toRemove) {
        Write-Host "Removing old CertKit cert: $($old.Thumbprint) ($($old.FriendlyName))"
        $store.Remove($old)
    }

    Write-Host "Cleaned up $($toRemove.Count) old cert(s), kept newest 2."
} finally {
    $store.Close()
}
`, escapePowerShellString(certificateId), escapePowerShellString(certificateId))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("cleanupOldCertKitCerts", out)
	return err
}

func logPowerShellOutput(name, output string) {
	output = strings.TrimSpace(output)
	if output == "" {
		return
	}
	log.Printf("PowerShell (%s): %s", name, output)
}
