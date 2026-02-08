package install

import (
	"fmt"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

func unregisterAgent(configPath string) {
	cfg, err := loadConfigForUnregister(configPath)
	if err != nil {
		log.Printf("Agent unregister skipped: %v", err)
		return
	}

	if err := api.UnregisterAgent(cfg); err != nil {
		log.Printf("Agent unregister failed for %s: %v", cfg.Agent.AgentId, err)
		return
	}

	log.Printf("Agent unregister succeeded for %s", cfg.Agent.AgentId)
}

func loadConfigForUnregister(configPath string) (config.Config, error) {
	cfg, err := config.ReadConfigFile(configPath)
	if err != nil {
		return cfg, err
	}

	if strings.TrimSpace(cfg.ApiBase) == "" {
		return cfg, fmt.Errorf("config %s missing api_base", configPath)
	}
	if cfg.Agent == nil || strings.TrimSpace(cfg.Agent.AgentId) == "" {
		return cfg, fmt.Errorf("config %s missing agent id", configPath)
	}
	if cfg.Auth == nil || cfg.Auth.KeyPair == nil || strings.TrimSpace(cfg.Auth.KeyPair.PrivateKey) == "" {
		return cfg, fmt.Errorf("config %s missing auth private key", configPath)
	}

	return cfg, nil
}
