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

func synchronizeRDPCertificate(cfg config.CertificateConfiguration, configChanged bool) api.AgentConfigStatusUpdate {
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
	}
	importedPfx := false
	appliedCert := false

	retryUpdateOnly := cfg.LastStatus == statusErrorUpdateCmd || cfg.LastStatus == statusWaitingWindow
	retryFull := cfg.LastStatus == statusPendingSync ||
		cfg.LastStatus == statusErrorGetCert ||
		cfg.LastStatus == statusErrorWriteCert ||
		cfg.LastStatus == statusErrorGeneral

	if cfg.Id == "" || cfg.CertificateId == "" {
		log.Printf("Skipping RDP config with missing ids (config_id=%s, certificate_id=%s)", cfg.Id, cfg.CertificateId)
		return api.AgentConfigStatusUpdate{}
	}

	role := strings.TrimSpace(cfg.PemDestination)
	if role == "" {
		status.Status = statusErrorGeneral
		status.Message = "Error: missing RDP role in PemDestination"
		return status
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
		log.Printf("Fetching new RDP PFX for config %s and certificate %s", cfg.Id, cfg.CertificateId)
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
		log.Printf("RDP apply requested (config=%s, cert=%s, role=%s, thumbprint=%s, needsFetch=%t, configChanged=%t, retryUpdateOnly=%t, retryFull=%t)",
			cfg.Id, cfg.CertificateId, role, thumbprint, needsFetch, configChanged, retryUpdateOnly, retryFull)

		if strings.EqualFold(role, "TerminalServices") {
			err = applyTerminalServicesCertificate(thumbprint)
		} else {
			err = applyRDCertificate(thumbprint, role)
		}

		if err != nil {
			status.Status = statusErrorUpdateCmd
			status.Message = fmt.Sprintf("Error applying RDP certificate for role %s: %v", role, err)
			return status
		}
		appliedCert = true
	}

	if importedPfx {
		if err := cleanupOldCertKitCerts(cfg.CertificateId); err != nil {
			log.Printf("Warning: failed to clean up old certificates: %v", err)
		}
	}

	if importedPfx || appliedCert {
		log.Printf("RDP synchronization complete for (config=%s, role=%s). (imported_pfx=%t, applied_cert=%t)", cfg.Id, role, importedPfx, appliedCert)
	} else {
		log.Printf("RDP configuration (config=%s, role=%s) synchronization checks complete.  No action taken, everything up to date.", cfg.Id, role)
	}

	status.Status = statusSynced
	return status
}

func applyTerminalServicesCertificate(thumbprint string) error {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for Terminal Services")
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'

$thumb = '%s'
$certPath = "Cert:\LocalMachine\My\" + $thumb
if (-not (Test-Path $certPath)) {
    throw "Certificate $thumb not found in LocalMachine\My store."
}

$tsSettings = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -ErrorAction Stop |
    Select-Object -First 1

if (-not $tsSettings) {
    throw "Unable to find Terminal Services general settings via CIM."
}

$currentThumb = ($tsSettings.SSLCertificateSHA1Hash -replace '\s', '').ToUpper()
if ($currentThumb -eq $thumb.ToUpper()) {
    Write-Host "Terminal Services certificate already set to $thumb. No update needed."
    return
}

$tsPath = $tsSettings | Get-CimInstance
Set-CimInstance -InputObject $tsPath -Property @{ SSLCertificateSHA1Hash = $thumb } -ErrorAction Stop

Write-Host "Terminal Services certificate updated to $thumb."
`, escapePowerShellString(thumbprint))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyTerminalServicesCertificate", out)
	return err
}

func applyRDCertificate(thumbprint string, role string) error {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for RD certificate role %s", role)
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'

try { Import-Module RemoteDesktopServices -ErrorAction Stop } catch {}

$thumb = '%s'
$role = '%s'

$certPath = "Cert:\LocalMachine\My\" + $thumb
if (-not (Test-Path $certPath)) {
    throw "Certificate $thumb not found in LocalMachine\My store."
}

Set-RDCertificate -Role $role -Thumbprint $thumb -Force -ErrorAction Stop

Write-Host "RD certificate for role '$role' updated to $thumb."
`, escapePowerShellString(thumbprint), escapePowerShellString(role))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyRDCertificate", out)
	return err
}
