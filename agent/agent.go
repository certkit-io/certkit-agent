package agent

import (
	"fmt"
	"log"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/inventory"
	"github.com/certkit-io/certkit-agent/utils"
)

func PollAndSync(forceSync bool) {
	configChanged, err := PollForConfiguration()
	if err != nil {
		reportAgentError(err, "", "")
		return
	}
	if utils.IsAgentUnauthorized() {
		return
	}
	if !configChanged && !forceSync {
		return
	}

	statuses := SynchronizeCertificates(configChanged)
	if len(statuses) > 0 {
		if err := api.UpdateConfigStatus(statuses); err != nil {
			reportAgentError(err, "", "")
		}
	}
}

func NeedsRegistration() bool {
	return config.CurrentConfig.Agent == nil || config.CurrentConfig.Agent.AgentId == ""
}

func DoRegistration() {
	if config.CurrentConfig.Bootstrap == nil || config.CurrentConfig.Bootstrap.RegistrationKey == "" {
		log.Printf("Error: missing registration key for agent bootstrap")
		return
	}

	response, err := api.RegisterAgent()
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	config.CurrentConfig.Agent = &config.AgentCreds{AgentId: response.AgentId}

	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		log.Printf("Error saving config: %v", err)
		return
	}

	log.Printf("Registered agent: %s", response.AgentId)

	SendInventory()
}

func PollForConfiguration() (configChanged bool, err error) {
	response, err := api.PollForConfiguration()
	if err != nil {
		return false, err
	}

	isLocked, err := config.IsLocked(config.CurrentPath)
	if err != nil {
		return false, err
	}

	if response == nil {
		return false, nil
	}

	if response.LockRequested {
		if err := config.CreateLockFile(config.CurrentPath); err != nil {
			return false, err
		}
		log.Printf("Lock requested. Agent now locked. Lock file created at %s", config.LockFilePath(config.CurrentPath))
		isLocked = true

		// Immediately re-poll once so the server sees is_locked=true in the normal loop.
		_, err := api.PollForConfiguration()
		if err != nil {
			return false, err
		}
	}

	if isLocked {
		changed := applyLockedConfigUpdates(response.UpdatedCertificateConfigurations)
		if !changed {
			return false, nil
		}
	} else {
		config.CurrentConfig.CertificateConfigurations = response.UpdatedCertificateConfigurations
	}

	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		return false, err
	}

	return true, nil
}

func applyLockedConfigUpdates(updated []config.CertificateConfiguration) bool {
	if len(updated) == 0 || len(config.CurrentConfig.CertificateConfigurations) == 0 {
		return false
	}

	changed := false
	byID := make(map[string]config.CertificateConfiguration, len(updated))
	for _, cfg := range updated {
		if cfg.Id == "" {
			continue
		}
		byID[cfg.Id] = cfg
	}

	for i := range config.CurrentConfig.CertificateConfigurations {
		current := &config.CurrentConfig.CertificateConfigurations[i]
		incoming, ok := byID[current.Id]
		if !ok {
			continue
		}

		if !timePtrEqual(current.LastCertificateUpdateDate, incoming.LastCertificateUpdateDate) {
			current.LastCertificateUpdateDate = incoming.LastCertificateUpdateDate
			changed = true
		}
		if current.LatestCertificateSha1 != incoming.LatestCertificateSha1 {
			current.LatestCertificateSha1 = incoming.LatestCertificateSha1
			changed = true
		}
	}

	return changed
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(*b)
}

func SendInventory() {
	items, err := inventory.Collect()
	if err != nil {
		reportAgentError(fmt.Errorf("collect inventory: %w", err), "", "")
		return
	}

	if err := api.UpdateInventory(items); err != nil {
		reportAgentError(fmt.Errorf("update inventory: %w", err), "", "")
		return
	}
}

func reportAgentError(err error, configId string, certificateId string) {
	if err == nil {
		return
	}

	if reportErr := api.ReportAgentError(err.Error(), configId, certificateId); reportErr != nil {
		log.Printf("Error reporting agent error: %v", reportErr)
	}
	log.Printf("Error: %v", err)
}
