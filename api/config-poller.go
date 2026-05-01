package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/certkit-io/certkit-agent/auth"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

type ConfigurationPollRequest struct {
	CertificateConfigurations []PollRequestCertificateConfig `json:"certificate_configurations"`
	IsLocked                  bool                           `json:"is_locked"`
	ForceFullSync             bool                           `json:"force_full_sync,omitempty"`
}

type PollRequestCertificateConfig struct {
	CertificateConfigurationId  string    `json:"config_id"`
	LastConfigurationUpdateDate time.Time `json:"last_configuration_update_date"`
	LastCertificateUpdateDate   time.Time `json:"last_certificate_update_date"`
	LatestCertificateSha1       string    `json:"latest_certificate_sha1"`
}

// ConfigurationPollResponse is the agent-facing decoded poll response.
// VariablesByConfigId is memory-only — json:"-" prevents accidental serialization.
type ConfigurationPollResponse struct {
	UpdatedCertificateConfigurations []config.CertificateConfiguration `json:"updated_certificate_configurations"`
	LockRequested                    bool                              `json:"lock_requested"`
	Keystore                         *config.KeystoreConfig            `json:"keystore,omitempty"`
	UpdateAvailable                  *UpdateSignal                     `json:"update_available,omitempty"`
	VariablesByConfigId              map[string][]utils.UpdateVariable `json:"-"`
}

// pollResponseConfig is the wire shape of an entry in updated_certificate_configurations.
// It mirrors config.CertificateConfiguration but adds UpdateVariables, which never
// reaches the disk-shaped CertificateConfiguration that gets persisted via SaveConfig.
type pollResponseConfig struct {
	config.CertificateConfiguration
	UpdateVariables []utils.UpdateVariable `json:"update_variables,omitempty"`
}

type pollResponseWire struct {
	UpdatedCertificateConfigurations []pollResponseConfig   `json:"updated_certificate_configurations"`
	LockRequested                    bool                   `json:"lock_requested"`
	Keystore                         *config.KeystoreConfig `json:"keystore,omitempty"`
	UpdateAvailable                  *UpdateSignal          `json:"update_available,omitempty"`
}

type UpdateSignal struct {
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
}

func PollForConfiguration(forceFullSync bool) (*ConfigurationPollResponse, error) {
	if config.CurrentConfig.Agent == nil || config.CurrentConfig.Agent.AgentId == "" {
		return nil, fmt.Errorf("missing agent id")
	}

	requestConfigs := make([]PollRequestCertificateConfig, 0, len(config.CurrentConfig.CertificateConfigurations))
	for _, cfg := range config.CurrentConfig.CertificateConfigurations {
		lastConfigurationUpdate := time.Time{}
		if cfg.LastConfigurationUpdateDate != nil {
			lastConfigurationUpdate = *cfg.LastConfigurationUpdateDate
		}
		lastCertificateUpdate := time.Time{}
		if cfg.LastCertificateUpdateDate != nil {
			lastCertificateUpdate = *cfg.LastCertificateUpdateDate
		}
		requestConfigs = append(requestConfigs, PollRequestCertificateConfig{
			CertificateConfigurationId:  cfg.Id,
			LastConfigurationUpdateDate: lastConfigurationUpdate,
			LastCertificateUpdateDate:   lastCertificateUpdate,
			LatestCertificateSha1:       cfg.LatestCertificateSha1,
		})
	}

	isLocked, err := config.IsLocked(config.CurrentPath)
	if err != nil {
		return nil, fmt.Errorf("check lock file: %w", err)
	}

	payload := ConfigurationPollRequest{
		CertificateConfigurations: requestConfigs,
		IsLocked:                  isLocked,
		ForceFullSync:             forceFullSync,
	}

	requestBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/%s/poll-config", config.CurrentConfig.ApiBase, config.CurrentConfig.Agent.AgentId),
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	privKey, err := config.CurrentConfig.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}

	if err := auth.SignRequest(req, config.CurrentConfig.Agent.AgentId, config.CurrentConfig.Version.Version, privKey, time.Now()); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		utils.MarkAgentAuthorized()
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden {
		utils.MarkAgentUnauthorized()
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll failed: status=%d body=%.100s", resp.StatusCode, body)
	}

	utils.MarkAgentAuthorized()

	var wire pollResponseWire
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("decode poll response: %w", err)
	}

	configs := make([]config.CertificateConfiguration, 0, len(wire.UpdatedCertificateConfigurations))
	varsByID := make(map[string][]utils.UpdateVariable)
	for _, entry := range wire.UpdatedCertificateConfigurations {
		configs = append(configs, entry.CertificateConfiguration)
		if entry.CertificateConfiguration.Id != "" && len(entry.UpdateVariables) > 0 {
			varsByID[entry.CertificateConfiguration.Id] = entry.UpdateVariables
		}
	}

	return &ConfigurationPollResponse{
		UpdatedCertificateConfigurations: configs,
		LockRequested:                    wire.LockRequested,
		Keystore:                         wire.Keystore,
		UpdateAvailable:                  wire.UpdateAvailable,
		VariablesByConfigId:              varsByID,
	}, nil
}
