package agent

import (
	"fmt"
	"log"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/inventory"
)

func PollAndSync(forceSync bool) {
	configChanged, err := PollForConfiguration()
	if err != nil {
		reportAgentError(err, "", "")
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

	if response == nil {
		return false, nil
	}

	config.CurrentConfig.CertificateConfigurations = response.UpdatedCertificateConfigurations
	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		return false, err
	}

	return true, nil
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
