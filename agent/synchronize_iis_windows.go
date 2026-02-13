//go:build windows

package agent

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func synchronizeIISCertificate(cfg config.CertificateConfiguration, configChanged bool) api.AgentConfigStatusUpdate {
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
	}
	importedPfx := false
	updatedBinding := false

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

		if err := importPfxBytesToStore(resp.PfxBytes, resp.Password); err != nil {
			status.Status = statusErrorWriteCert
			status.Message = fmt.Sprintf("Error importing PFX: %v", err)
			return status
		}
		importedPfx = true

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
		updatedBinding = true
	}

	if importedPfx || updatedBinding {
		log.Printf("IIS synchronization complete for (config=%s). (imported_pfx=%t, updated_binding=%t)", cfg.Id, importedPfx, updatedBinding)
	} else {
		log.Printf("IIS configuration (config=%s) synchronization checks complete.  No action taken, everything up to date.", cfg.Id)
	}

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
