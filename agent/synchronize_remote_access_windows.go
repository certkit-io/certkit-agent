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

func synchronizeRemoteAccessCertificate(cfg config.CertificateConfiguration, configChanged bool) api.AgentConfigStatusUpdate {
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
	}
	importedPfx := false
	appliedSsl := false

	retryUpdateOnly := cfg.LastStatus == statusErrorUpdateCmd || cfg.LastStatus == statusWaitingWindow
	retryFull := cfg.LastStatus == statusPendingSync ||
		cfg.LastStatus == statusErrorGetCert ||
		cfg.LastStatus == statusErrorWriteCert ||
		cfg.LastStatus == statusErrorGeneral

	if cfg.Id == "" || cfg.CertificateId == "" {
		log.Printf("Skipping RemoteAccess config with missing ids (config_id=%s, certificate_id=%s)", cfg.Id, cfg.CertificateId)
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
		status.Status = statusErrorGeneral
		status.Message = fmt.Sprintf("Error checking certificate store: %v", err)
		return status
	}
	needsFetch = !exists

	shouldFetch := needsFetch || retryFull
	shouldApply := needsFetch || configChanged || retryUpdateOnly || retryFull

	if shouldFetch {
		log.Printf("Fetching new RemoteAccess PFX for config %s and certificate %s", cfg.Id, cfg.CertificateId)
		resp, err := api.FetchPfx(cfg.Id, cfg.CertificateId)
		if err != nil {
			status.Status = statusErrorGetCert
			status.Message = fmt.Sprintf("Error fetching PFX: %v", err)
			log.Print(status.Message)
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

		if err := setCertFriendlyName(thumbprint, cfg.CertificateId); err != nil {
			log.Printf("Warning: failed to set certificate friendly name: %v", err)
		}
	}

	if shouldApply {
		log.Printf("RemoteAccess apply requested (config=%s, cert=%s, thumbprint=%s, needsFetch=%t, configChanged=%t, retryUpdateOnly=%t, retryFull=%t)",
			cfg.Id, cfg.CertificateId, thumbprint, needsFetch, configChanged, retryUpdateOnly, retryFull)
		if err := applyRemoteAccessSslCertificate(thumbprint, cfg.ConfigType); err != nil {
			status.Status = statusErrorUpdateCmd
			status.Message = fmt.Sprintf("Error applying RemoteAccess SSL certificate: %v", err)
			return status
		}
		appliedSsl = true
	}

	if importedPfx {
		if err := cleanupOldCertKitCerts(cfg.CertificateId); err != nil {
			log.Printf("Warning: failed to clean up old certificates: %v", err)
		}
	}

	if importedPfx || appliedSsl {
		log.Printf("RemoteAccess synchronization complete for (config=%s). (imported_pfx=%t, applied_cert=%t)", cfg.Id, importedPfx, appliedSsl)
	} else {
		log.Printf("RemoteAccess configuration (config=%s) synchronization checks complete.  No action taken, everything up to date.", cfg.Id)
	}

	status.Status = statusSynced
	return status
}

func applyRemoteAccessSslCertificate(thumbprint string, configType string) error {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for RemoteAccess binding")
	}

	isDirectAccess := strings.EqualFold(configType, "direct-access")

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
Import-Module RemoteAccess

$thumb = '%s'
$isDirectAccess = $%s
$serviceName = if ($isDirectAccess) { 'RaMgmtSvc' } else { 'RemoteAccess' }
$certPath = "Cert:\LocalMachine\My\" + $thumb
$cert = Get-ChildItem $certPath -ErrorAction Stop

$svcBefore = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$wasRunning = $svcBefore -and $svcBefore.Status -eq 'Running'

Set-RemoteAccess -SslCertificate $cert -ErrorAction Stop

if (-not $wasRunning) {
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
} else {
    Restart-Service -Name $serviceName -Force -ErrorAction Stop
}

$deadline = (Get-Date).AddSeconds(120)
$lastState = ""
while ((Get-Date) -lt $deadline) {
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        throw ($serviceName + " service not found.")
    }

    $state = $svc.Status.ToString()
    if ($state -ne $lastState) {
        Write-Host ($serviceName + " service state: " + $state)
        $lastState = $state
    }

    if ($svc.Status -eq 'Running') {
        Write-Host ("RemoteAccess SSL certificate updated. Active service: " + $serviceName)
        return
    }

    if ($svc.Status -eq 'Stopped') {
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 2
}

throw ($serviceName + " service did not reach Running within timeout after applying certificate.")
`, escapePowerShellString(thumbprint), fmt.Sprintf("%t", isDirectAccess))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyRemoteAccessSslCertificate", out)
	return err
}
