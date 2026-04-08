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

type windowsSyncConfig struct {
	serviceName string
	applyFn     func(thumbprint string) (string, error)
}

func synchronizeWindowsServiceCert(cfg config.CertificateConfiguration, change ConfigChange, svc windowsSyncConfig) api.AgentConfigStatusUpdate {
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
	}

	if cfg.Id == "" || cfg.CertificateId == "" {
		log.Printf("Skipping %s config with missing ids (config_id=%s, certificate_id=%s)", svc.serviceName, cfg.Id, cfg.CertificateId)
		return api.AgentConfigStatusUpdate{}
	}

	thumbprint := normalizeThumbprint(cfg.LatestCertificateSha1)
	if thumbprint == "" {
		status.Status = statusErrorGeneral
		status.Message = "Error: no thumbprint found in configuration"
		return status
	}

	retryUpdateOnly := cfg.LastStatus == statusErrorUpdateCmd || cfg.LastStatus == statusWaitingWindow
	retryFull := cfg.LastStatus == statusPendingSync ||
		cfg.LastStatus == statusErrorGetCert ||
		cfg.LastStatus == statusErrorWriteCert ||
		cfg.LastStatus == statusErrorGeneral

	exists, err := certInStore(thumbprint)
	if err != nil {
		status.Status = statusErrorGeneral
		status.Message = fmt.Sprintf("Error checking certificate store: %v", err)
		return status
	}
	needsFetch := !exists

	shouldFetch := needsFetch || retryFull
	shouldApply := needsFetch || change.Changed || retryUpdateOnly || retryFull

	importedPfx := false
	if shouldFetch {
		log.Printf("Fetching new %s PFX for config %s and certificate %s", svc.serviceName, cfg.Id, cfg.CertificateId)
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

	appliedCert := false
	if shouldApply {
		out, err := svc.applyFn(thumbprint)
		if err != nil {
			status.Status = statusErrorUpdateCmd
			status.Message = fmt.Sprintf("Error applying %s certificate: %v", svc.serviceName, err)
			return status
		}
		if out != "" {
			status.Message = out
		}
		appliedCert = true
	}

	if importedPfx {
		if err := cleanupOldCertKitCerts(cfg.CertificateId); err != nil {
			log.Printf("Warning: failed to clean up old certificates: %v", err)
		}
	}

	if importedPfx || appliedCert {
		log.Printf("%s synchronization complete for (config=%s). (imported_pfx=%t, applied_cert=%t)", svc.serviceName, cfg.Id, importedPfx, appliedCert)
	} else {
		log.Printf("%s configuration (config=%s) synchronization checks complete.  No action taken, everything up to date.", svc.serviceName, cfg.Id)
	}

	status.Status = statusSynced
	return status
}

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
