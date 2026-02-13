//go:build windows

package agent

import (
	"fmt"
	"log"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func synchronizeRRASCertificate(cfg config.CertificateConfiguration, configChanged bool) api.AgentConfigStatusUpdate {
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
	}
	importedPfx := false
	appliedRrasSsl := false

	retryFull := cfg.LastStatus == statusErrorGetCert ||
		cfg.LastStatus == statusErrorWriteCert ||
		cfg.LastStatus == statusErrorGeneral

	if cfg.Id == "" || cfg.CertificateId == "" {
		log.Printf("Skipping RRAS config with missing ids (config_id=%s, certificate_id=%s)", cfg.Id, cfg.CertificateId)
		return api.AgentConfigStatusUpdate{}
	}

	thumbprint := normalizeThumbprint(cfg.LatestCertificateSha1)

	if thumbprint == "" {
		status.Status = statusErrorGeneral
		status.Message = "Error: no thumbprint found in configuration"
		return status
	}

	needsFetch := false
	exists, err := certInStore(thumbprint)
	if err != nil {
		status.Status = statusErrorGetCert
		status.Message = fmt.Sprintf("Error checking certificate store: %v", err)
		return status
	}
	needsFetch = !exists

	if needsFetch || retryFull {
		log.Printf("Fetching new RRAS PFX for config %s and certificate %s", cfg.Id, cfg.CertificateId)
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
	}

	if needsFetch || retryFull {
		log.Printf("RRAS apply requested (config=%s, cert=%s, thumbprint=%s, needsFetch=%t, retryFull=%t)",
			cfg.Id, cfg.CertificateId, thumbprint, needsFetch, retryFull)
		if err := applyRRASSslCertificate(thumbprint); err != nil {
			status.Status = statusErrorUpdateCmd
			status.Message = fmt.Sprintf("Error applying RRAS SSL certificate: %v", err)
			return status
		}
		appliedRrasSsl = true
	}

	if importedPfx || appliedRrasSsl {
		log.Printf("RRAS synchronization complete for (config=%s). (imported_pfx=%t, applied_cert=%t)", cfg.Id, importedPfx, appliedRrasSsl)
	} else {
		log.Printf("RRAS configuration (config=%s) synchronization checks complete.  No action taken, everything up to date.", cfg.Id)
	}

	status.Status = statusSynced
	return status
}

func applyRRASSslCertificate(thumbprint string) error {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for RRAS binding")
	}

	script := fmt.Sprintf(`
Import-Module RemoteAccess

$thumb = '%s'
$certPath = "Cert:\LocalMachine\My\" + $thumb
$cert = Get-ChildItem $certPath -ErrorAction Stop

Set-RemoteAccess -SslCertificate $cert -ErrorAction Stop

Restart-Service -Name RemoteAccess -Force -ErrorAction Stop

$deadline = (Get-Date).AddSeconds(120)
$lastState = ""
while ((Get-Date) -lt $deadline) {
    $svc = Get-Service -Name RemoteAccess -ErrorAction SilentlyContinue
    if (-not $svc) {
        throw "RemoteAccess service not found."
    }

    $state = $svc.Status.ToString()
    if ($state -ne $lastState) {
        Write-Host ("RemoteAccess service state: " + $state)
        $lastState = $state
    }

    if ($svc.Status -eq 'Running') {
        Write-Host "RRAS SSL certificate updated."
        return
    }

    if ($svc.Status -eq 'Stopped') {
        Start-Service -Name RemoteAccess -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 2
}

throw "RemoteAccess service did not reach Running within timeout after applying certificate."
`, escapePowerShellString(thumbprint))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyRRASSslCertificate", out)
	return err
}
