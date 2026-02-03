package agent

import (
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

const (
	statusSynced         = "SYNCED"
	statusPendingSync    = "PENDING_SYNC"
	statusErrorUpdateCmd = "ERROR_UPDATE_CMD"
	statusErrorGetCert   = "ERROR_GET_CERTS"
	statusErrorWriteCert = "ERROR_WRITE_CERTS"
	statusErrorGeneral   = "ERROR_GENERAL"
)

func SynchronizeCertificates(configChanged bool) []api.AgentConfigStatusUpdate {
	log.Print("Synchronizing certificates...")
	statuses := make([]api.AgentConfigStatusUpdate, 0, len(config.CurrentConfig.CertificateConfigurations))
	configDirty := false

	for i := range config.CurrentConfig.CertificateConfigurations {
		cfg := &config.CurrentConfig.CertificateConfigurations[i]
		status := synchronizeCertificate(*cfg, configChanged)
		if status.ConfigId != "" {
			statuses = append(statuses, status)
			if status.Status != "" && status.Status != cfg.LastStatus {
				cfg.LastStatus = status.Status
				configDirty = true
			}
		}
	}
	if configDirty {
		if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
			reportAgentError(err, "", "")
		}
	}
	return statuses
}

func synchronizeCertificate(cfg config.CertificateConfiguration, configChanged bool) api.AgentConfigStatusUpdate {
	if strings.EqualFold(cfg.ConfigType, "iis") {
		return synchronizeIISCertificate(cfg, configChanged)
	}

	log.Printf("Beginning synchronization for %s", cfg.Id)
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
	}
	retryUpdateOnly := cfg.LastStatus == statusErrorUpdateCmd
	retryFull := cfg.LastStatus == statusPendingSync ||
		cfg.LastStatus == statusErrorGetCert ||
		cfg.LastStatus == statusErrorWriteCert ||
		cfg.LastStatus == statusErrorGeneral

	if cfg.PemDestination == "" || (!cfg.AllInOne && cfg.KeyDestination == "") {
		log.Printf("Skipping certificate config %s: missing destination path(s)", cfg.Id)
		status.Status = statusErrorGeneral
		status.Message = "Error: missing destination path(s) in configuration"
		return status
	}
	if cfg.Id == "" || cfg.CertificateId == "" {
		log.Printf("Skipping certificate config with missing ids (config_id=%s, certificate_id=%s)", cfg.Id, cfg.CertificateId)
		return api.AgentConfigStatusUpdate{}
	}

	needsFetch, err := needsCertificateFetch(cfg)
	if err != nil {
		status.Status = statusErrorGetCert
		status.Message = fmt.Sprintf("Error checking whether we need to fetch certificate: %v", err)
		return status
	}

	if needsFetch || retryFull {
		log.Printf("Fetching new certificate for config %s and certificate %s", cfg.Id, cfg.CertificateId)
		response, err := api.FetchCertificate(cfg.Id, cfg.CertificateId)
		if err != nil {
			status.Status = statusErrorGetCert
			status.Message = fmt.Sprintf("Error fetching certificate: %v", err)
			return status
		}
		if response == nil {
			log.Printf("Received no-content reply from fetch for (config_id=%s, certificate_id=%s)", cfg.Id, cfg.CertificateId)
			status.Status = statusErrorGetCert
			status.Message = "Error: no issued certificate returned"
			return status
		}

		if err := writeCertificateFiles(cfg, response); err != nil {
			status.Status = statusErrorWriteCert
			status.Message = fmt.Sprintf("Error writing certificate files: %v", err)
			return status
		}
	} else {
		log.Printf("Certificate is up to date for config %s", cfg.Id)
	}

	if needsFetch || configChanged || retryUpdateOnly || retryFull {
		if !needsFetch && configChanged {
			log.Print("Running update cmd due to configuration change...")
		}
		if retryUpdateOnly || retryFull {
			log.Print("Retrying update command due to previous failure...")
		}
		if strings.TrimSpace(cfg.UpdateCmd) == "" {
			log.Print("No update command configured; skipping update command.")
		} else {
			if commandOutput, err := runUpdateCommand(cfg); err != nil {
				status.Status = statusErrorUpdateCmd
				status.Message = fmt.Sprintf("Error running update command: %v", err)
				return status
			} else {
				status.Message = fmt.Sprintf("Update command output: \n%s", commandOutput)
			}
		}
	}

	log.Printf("Synchronization complete for %s", cfg.Id)
	status.Status = statusSynced
	return status
}

func needsCertificateFetch(cfg config.CertificateConfiguration) (bool, error) {
	certExists, err := utils.FileExists(cfg.PemDestination)
	if err != nil {
		return false, err
	}

	if cfg.AllInOne {
		if !certExists {
			return true, nil
		}
	} else {
		keyExists, err := utils.FileExists(cfg.KeyDestination)
		if err != nil {
			return false, err
		}
		if strings.TrimSpace(cfg.ChainDestination) != "" {
			chainExists, err := utils.FileExists(cfg.ChainDestination)
			if err != nil {
				return false, err
			}
			if !chainExists {
				return true, nil
			}
		}
		if !certExists || !keyExists {
			return true, nil
		}
	}

	if !certExists {
		return true, nil
	}

	if cfg.LatestCertificateSha1 == "" {
		return true, nil
	}

	actualSha1, err := utils.GetCertificateSha1(cfg.PemDestination)
	if err != nil {
		return true, err
	}

	if !strings.EqualFold(actualSha1, cfg.LatestCertificateSha1) {
		return true, nil
	}

	return false, nil
}

func writeCertificateFiles(cfg config.CertificateConfiguration, response *api.FetchCertificateResponse) error {
	if response.CertificatePem == "" || response.KeyPem == "" {
		return fmt.Errorf("missing certificate or key payload")
	}

	if err := os.MkdirAll(filepath.Dir(cfg.PemDestination), 0o755); err != nil {
		return err
	}

	if cfg.AllInOne {
		merged := utils.MergeKeyAndCert(response.KeyPem, response.CertificatePem)
		log.Printf("Writing combined PEM to %s", cfg.PemDestination)
		if err := utils.WriteFileAtomic(cfg.PemDestination, []byte(merged), 0o600); err != nil {
			return err
		}
		return nil
	}

	chainDestination := strings.TrimSpace(cfg.ChainDestination)
	certPem := response.CertificatePem
	chainPem := ""
	if chainDestination != "" {
		leafPem, parsedChainPem, err := splitLeafAndChain(response.CertificatePem)
		if err != nil {
			return fmt.Errorf("split certificate pem: %w", err)
		}
		certPem = leafPem
		chainPem = parsedChainPem

		if err := os.MkdirAll(filepath.Dir(chainDestination), 0o755); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(filepath.Dir(cfg.KeyDestination), 0o755); err != nil {
		return err
	}

	log.Printf("Writing PEM to %s", cfg.PemDestination)
	if err := utils.WriteFileAtomic(cfg.PemDestination, []byte(certPem), 0o600); err != nil {
		return err
	}

	if chainDestination != "" {
		log.Printf("Writing chain PEM to %s", chainDestination)
		if err := utils.WriteFileAtomic(chainDestination, []byte(chainPem), 0o600); err != nil {
			return err
		}
	}

	log.Printf("Writing Private Key to %s", cfg.KeyDestination)
	if err := utils.WriteFileAtomic(cfg.KeyDestination, []byte(response.KeyPem), 0o600); err != nil {
		return err
	}

	return nil
}

func splitLeafAndChain(certPem string) (string, string, error) {
	data := []byte(certPem)
	var leaf []byte
	var chain []byte
	foundLeaf := false

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		encoded := pem.EncodeToMemory(block)
		if !foundLeaf {
			leaf = append(leaf, encoded...)
			foundLeaf = true
			continue
		}
		chain = append(chain, encoded...)
	}

	if !foundLeaf {
		return "", "", fmt.Errorf("no certificate block found in PEM")
	}

	return string(leaf), string(chain), nil
}

func runUpdateCommand(cfg config.CertificateConfiguration) (output string, err error) {
	if strings.TrimSpace(cfg.UpdateCmd) == "" {
		return "", nil
	}

	log.Printf("Running update command: '%s'", cfg.UpdateCmd)

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-NoProfile", "-Command", cfg.UpdateCmd)
	} else {
		cmd = exec.Command("sh", "-c", cfg.UpdateCmd)
	}

	combinedOutput, err := cmd.CombinedOutput()
	if len(combinedOutput) > 0 {
		log.Printf("Update command output for '%s':\n%s", cfg.UpdateCmd, string(combinedOutput))
	}
	if err != nil {
		return string(combinedOutput), fmt.Errorf("Update command failed: \n%w\n%s", err, string(combinedOutput))
	}

	return string(combinedOutput), nil
}
