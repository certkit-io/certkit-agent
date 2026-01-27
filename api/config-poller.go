package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/certkit-io/certkit-agent-alpha/auth"
	"github.com/certkit-io/certkit-agent-alpha/config"
)

type ConfigurationPollRequest struct {
	CertificateConfigurations []PollRequestCertificateConfig `json:"certificate_configurations"`
}

type PollRequestCertificateConfig struct {
	CertificateConfigurationId  string    `json:"config_id"`
	LastConfigurationUpdateDate time.Time `json:"last_configuration_update_date"`
	LastCertificateUpdateDate   time.Time `json:"last_certificate_update_date"`
	LatestCertificateSha1       string    `json:"latest_certificate_sha1"`
}

type ConfigurationPollResponse struct {
	UpdatedCertificateConfigurations []config.CertificateConfiguration `json:"updated_certificate_configurations"`
}

func PollForConfiguration() (*ConfigurationPollResponse, error) {
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

	payload := ConfigurationPollRequest{
		CertificateConfigurations: requestConfigs,
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
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden {
		log.Printf("Agent is not currently authorized.  Waiting for authorization from the CertKit server.")
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("poll failed: status=%d body=%s", resp.StatusCode, body)
	}

	var pollResp ConfigurationPollResponse
	if err := json.Unmarshal(body, &pollResp); err != nil {
		return nil, fmt.Errorf("decode poll response: %w", err)
	}

	return &pollResp, nil
}
