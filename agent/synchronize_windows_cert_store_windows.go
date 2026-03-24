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

func synchronizeWindowsCertStoreCertificate(cfg config.CertificateConfiguration, configChanged bool) api.AgentConfigStatusUpdate {
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
	}
	importedPfx := false
	ranUpdateCmd := false

	retryUpdateOnly := cfg.LastStatus == statusErrorUpdateCmd || cfg.LastStatus == statusWaitingWindow
	retryFull := cfg.LastStatus == statusPendingSync ||
		cfg.LastStatus == statusErrorGetCert ||
		cfg.LastStatus == statusErrorWriteCert ||
		cfg.LastStatus == statusErrorGeneral

	if cfg.Id == "" || cfg.CertificateId == "" {
		log.Printf("Skipping windows-cert-store config with missing ids (config_id=%s, certificate_id=%s)", cfg.Id, cfg.CertificateId)
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
		log.Printf("Fetching new PFX for windows-cert-store config %s and certificate %s", cfg.Id, cfg.CertificateId)
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
		if strings.TrimSpace(cfg.UpdateCmd) == "" {
			log.Print("No update command configured; skipping update command.")
		} else {
			out, err := runWindowsCertStoreUpdateCmd(thumbprint, cfg.UpdateCmd)
			if err != nil {
				status.Status = statusErrorUpdateCmd
				status.Message = fmt.Sprintf("Error running update command: %v", err)
				return status
			}
			if out != "" {
				status.Message = fmt.Sprintf("Update command output: \n%s", out)
			}
			ranUpdateCmd = true
		}
	}

	if importedPfx {
		if err := cleanupOldCertKitCerts(cfg.CertificateId); err != nil {
			log.Printf("Warning: failed to clean up old certificates: %v", err)
		}
	}

	if importedPfx || ranUpdateCmd {
		log.Printf("Windows cert store synchronization complete for (config=%s). (imported_pfx=%t, ran_update_cmd=%t)", cfg.Id, importedPfx, ranUpdateCmd)
	} else {
		log.Printf("Windows cert store configuration (config=%s) synchronization checks complete. No action taken, everything up to date.", cfg.Id)
	}

	status.Status = statusSynced
	return status
}

func runWindowsCertStoreUpdateCmd(thumbprint, updateCmd string) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for update command")
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$thumbprint = '%s'
$certificate = Get-Item "Cert:\LocalMachine\My\$thumbprint" -ErrorAction Stop

%s
`, escapePowerShellString(thumbprint), updateCmd)

	log.Printf("Running windows-cert-store update command: '%s'", updateCmd)
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("runWindowsCertStoreUpdateCmd", out)
	return out, err
}
