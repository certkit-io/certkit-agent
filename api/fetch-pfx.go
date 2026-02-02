package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/certkit-io/certkit-agent/auth"
	"github.com/certkit-io/certkit-agent/config"
)

type FetchPfxResponse struct {
	PfxBytes []byte
	Password string
}

func FetchPfx(configurationId string, certificateId string) (*FetchPfxResponse, error) {
	if config.CurrentConfig.Agent == nil || config.CurrentConfig.Agent.AgentId == "" {
		return nil, fmt.Errorf("missing agent id")
	}
	if configurationId == "" || certificateId == "" {
		return nil, fmt.Errorf("missing configuration or certificate id")
	}

	payload := FetchCertificateRequest{
		CertificateConfigurationId: configurationId,
		CertificateId:              certificateId,
	}

	requestBody, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal json: %w", err)
	}

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/agent/v1/%s/fetch-pfx", config.CurrentConfig.ApiBase, config.CurrentConfig.Agent.AgentId),
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode == http.StatusForbidden {
		log.Printf("Agent is not currently authorized.  Waiting for authorization from the CertKit server.")
		return nil, nil
	} else if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch pfx failed: status=%d body=%s", resp.StatusCode, body)
	}

	password := resp.Header.Get("X-Certkit-Pfx-Password")

	return &FetchPfxResponse{
		PfxBytes: body,
		Password: password,
	}, nil
}
