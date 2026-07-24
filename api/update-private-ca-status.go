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

type AgentPrivateCaStatusUpdate struct {
	CaId             string    `json:"ca_id"`
	Status           string    `json:"status"`
	InstalledByAgent bool      `json:"installed_by_agent"`
	Message          string    `json:"message,omitempty"`
	LastStatusDate   time.Time `json:"last_status_date"`
}

type AgentPrivateCaStatusUpdateBatch struct {
	Updates []AgentPrivateCaStatusUpdate `json:"updates"`
}

func UpdatePrivateCaStatus(updates []AgentPrivateCaStatusUpdate) error {
	if config.CurrentConfig.Agent == nil || config.CurrentConfig.Agent.AgentId == "" {
		return fmt.Errorf("missing agent id")
	}
	if len(updates) == 0 {
		return fmt.Errorf("no updates to send")
	}

	payload := AgentPrivateCaStatusUpdateBatch{
		Updates: updates,
	}

	requestBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/%s/update-private-ca-status", config.CurrentConfig.ApiBase, config.CurrentConfig.Agent.AgentId),
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

	return fmt.Errorf("update private ca status failed: status=%d body=%s", resp.StatusCode, body)
}
