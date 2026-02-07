package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/auth"
	"github.com/certkit-io/certkit-agent/config"
)

func UnregisterAgent(cfg config.Config) error {
	if strings.TrimSpace(cfg.ApiBase) == "" {
		return fmt.Errorf("missing api base")
	}
	if cfg.Agent == nil || strings.TrimSpace(cfg.Agent.AgentId) == "" {
		return fmt.Errorf("missing agent id")
	}
	if cfg.Auth == nil || cfg.Auth.KeyPair == nil {
		return fmt.Errorf("missing auth key pair")
	}

	requestBody := []byte("{}")

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/%s/unregister", cfg.ApiBase, cfg.Agent.AgentId),
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	privKey, err := cfg.Auth.KeyPair.DecodePrivateKey()
	if err != nil {
		return fmt.Errorf("decode private key: %w", err)
	}

	if err := auth.SignRequest(req, cfg.Agent.AgentId, cfg.Version.Version, privKey, time.Now()); err != nil {
		return fmt.Errorf("sign request: %w", err)
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http do: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unregister failed: status=%d read body: %w", resp.StatusCode, err)
	}

	return fmt.Errorf("unregister failed: status=%d body=%s", resp.StatusCode, body)
}
