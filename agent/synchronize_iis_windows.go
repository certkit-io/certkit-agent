//go:build windows

package agent

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func synchronizeIISCertificate(cfg config.CertificateConfiguration, configChanged bool) api.AgentConfigStatusUpdate {
	log.Printf("Beginning IIS synchronization for %s", cfg.Id)
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
	}

	retryUpdateOnly := cfg.LastStatus == statusErrorUpdateCmd
	retryFull := cfg.LastStatus == statusPendingSync ||
		cfg.LastStatus == statusErrorGetCert ||
		cfg.LastStatus == statusErrorWriteCert ||
		cfg.LastStatus == statusErrorGeneral

	siteName, port, err := parseIISDestination(cfg.PemDestination)
	if err != nil {
		status.Status = statusErrorGeneral
		status.Message = err.Error()
		return status
	}
	if cfg.Id == "" || cfg.CertificateId == "" {
		log.Printf("Skipping IIS config with missing ids (config_id=%s, certificate_id=%s)", cfg.Id, cfg.CertificateId)
		return api.AgentConfigStatusUpdate{}
	}

	thumbprint := normalizeThumbprint(cfg.LatestCertificateSha1)
	needsFetch := false
	if thumbprint != "" {
		exists, err := certInStore(thumbprint)
		if err != nil {
			status.Status = statusErrorGetCert
			status.Message = fmt.Sprintf("Error checking certificate store: %v", err)
			return status
		}
		needsFetch = !exists
	}

	if needsFetch || retryFull {
		log.Printf("Fetching new PFX for config %s and certificate %s", cfg.Id, cfg.CertificateId)
		resp, err := api.FetchPfx(cfg.Id, cfg.CertificateId)
		if err != nil {
			status.Status = statusErrorGetCert
			status.Message = fmt.Sprintf("Error fetching PFX: %v", err)
			return status
		}
		if resp == nil || len(resp.PfxBytes) == 0 {
			status.Status = statusErrorGetCert
			status.Message = "Error: no issued PFX returned"
			return status
		}

		tempFile, err := os.CreateTemp("", "certkit-*.pfx")
		if err != nil {
			status.Status = statusErrorWriteCert
			status.Message = fmt.Sprintf("Error creating temp PFX: %v", err)
			return status
		}
		tempPath := tempFile.Name()
		if _, err := tempFile.Write(resp.PfxBytes); err != nil {
			_ = tempFile.Close()
			_ = os.Remove(tempPath)
			status.Status = statusErrorWriteCert
			status.Message = fmt.Sprintf("Error writing temp PFX: %v", err)
			return status
		}
		if err := tempFile.Close(); err != nil {
			_ = os.Remove(tempPath)
			status.Status = statusErrorWriteCert
			status.Message = fmt.Sprintf("Error closing temp PFX: %v", err)
			return status
		}
		defer os.Remove(tempPath)

		if err := importPfxToStore(tempPath, resp.Password); err != nil {
			status.Status = statusErrorWriteCert
			status.Message = fmt.Sprintf("Error importing PFX: %v", err)
			return status
		}

		if thumbprint != "" {
			if exists, err := certInStore(thumbprint); err == nil && !exists {
				log.Printf("Warning: thumbprint %s not found after import", thumbprint)
			}
		}
	}

	if needsFetch || configChanged || retryUpdateOnly || retryFull {
		if err := applyIISBinding(siteName, port, thumbprint); err != nil {
			status.Status = statusErrorUpdateCmd
			status.Message = fmt.Sprintf("Error applying IIS binding: %v", err)
			return status
		}
	}

	log.Printf("IIS synchronization complete for %s", cfg.Id)
	status.Status = statusSynced
	return status
}

func parseIISDestination(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("Error: missing IIS destination (expected site:port)")
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("Error: invalid IIS destination %q (expected site:port)", value)
	}
	site := strings.TrimSpace(parts[0])
	port := strings.TrimSpace(parts[1])
	if site == "" || port == "" {
		return "", "", fmt.Errorf("Error: invalid IIS destination %q (expected site:port)", value)
	}
	return site, port, nil
}

func normalizeThumbprint(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, " ", "")
	return strings.ToUpper(value)
}

func certInStore(thumbprint string) (bool, error) {
	script := fmt.Sprintf(`
Import-Module WebAdministration
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
Import-Module WebAdministration
$pwd = ConvertTo-SecureString -String '%s' -AsPlainText -Force
Import-PfxCertificate -FilePath '%s' -CertStoreLocation 'Cert:\LocalMachine\My' -Password $pwd | Out-Null
`, escapePowerShellString(password), escapePowerShellString(pfxPath))
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("importPfxToStore", out)
	return err
}

func applyIISBinding(siteName, port, thumbprint string) error {
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for IIS binding")
	}
	script := fmt.Sprintf(`
Import-Module WebAdministration

$site     = '%s'
$port     = '%s'
$newThumb = '%s'

$bindings = Get-WebBinding -Name $site -Protocol https -Port $port
if (-not $bindings) { throw "No HTTPS bindings found for site '$site' on port $port." }

foreach ($binding in @($bindings)) {
    # Resolve currently bound cert thumbprint (if any)
    $currentThumbprint = if ($binding.CertificateHash) {
        $p = "Cert:\LocalMachine\My\$(($binding.CertificateHash -join ''))"
        if (Test-Path $p) { (Get-Item $p).Thumbprint }
    }

    if ($currentThumbprint -eq $newThumb) {
        Write-Host "Certificate already current for $site ($($binding.bindingInformation)). No update needed."
        continue
    }

    Write-Host "Updating $site ($($binding.bindingInformation)) -> $newThumb..."

    $binding.AddSslCertificate($newThumb, "My")

    # Optional cleanup: remove previous cert from LocalMachine\My
    if ($currentThumbprint -and $currentThumbprint -ne $newThumb) {
        Get-ChildItem "Cert:\LocalMachine\My\$currentThumbprint" -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Host "Removing old cert: $($_.Thumbprint)"
                Remove-Item $_.PSPath -Force
            }
    }
}

Write-Host "IIS bindings updated."
`, escapePowerShellString(siteName), escapePowerShellString(port), escapePowerShellString(thumbprint))
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyIISBinding", out)
	return err
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
