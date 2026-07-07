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

type DomainMonitoringResultUpdate struct {
	DomainId         string `json:"domain_id"`
	Timestamp        string `json:"timestamp"`
	Success          bool   `json:"success"`
	NotBefore        string `json:"not_before,omitempty"`
	Expires          string `json:"expires,omitempty"`
	Issuer           string `json:"issuer,omitempty"`
	Thumbprint       string `json:"thumbprint,omitempty"`
	Sha256           string `json:"sha256,omitempty"`
	SerialNumber     string `json:"serial_number,omitempty"`
	FailureReason    string `json:"failure_reason,omitempty"`
	ChainStatusFlags *int   `json:"chain_status_flags,omitempty"`
}

type DomainMonitoringResultBatch struct {
	Results []DomainMonitoringResultUpdate `json:"results"`
}

func UpdateMonitoringResults(results []DomainMonitoringResultUpdate) error {
	if config.CurrentConfig.Agent == nil || config.CurrentConfig.Agent.AgentId == "" {
		return fmt.Errorf("missing agent id")
	}
	if len(results) == 0 {
		return fmt.Errorf("no results to send")
	}

	payload := DomainMonitoringResultBatch{
		Results: results,
	}

	requestBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/%s/update-monitoring-results", config.CurrentConfig.ApiBase, config.CurrentConfig.Agent.AgentId),
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	privKey, err := config.CurrentConfig.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}

	if err := auth.SignRequest(req, config.CurrentConfig.Agent.AgentId, config.CurrentConfig.Version.Version, privKey, time.Now()); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	resp, err := doRequest(newHTTPClient(), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode == http.StatusForbidden {
		utils.MarkAgentUnauthorized()
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	return fmt.Errorf("update monitoring results failed: status=%d body=%s", resp.StatusCode, body)
}
