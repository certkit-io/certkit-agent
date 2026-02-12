package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"runtime"
	"strings"

	"github.com/certkit-io/certkit-agent/agent"
	"github.com/certkit-io/certkit-agent/config"
)

func doRegister(configPath string, key string) error {
	key = strings.TrimSpace(key)
	if key == "" {
		return fmt.Errorf("--key is required")
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := config.CreateInitialConfig(configPath, key); err != nil {
			return err
		}
	}

	if _, err := config.LoadConfig(configPath, Version()); err != nil {
		return err
	}

	if config.CurrentConfig.Bootstrap == nil {
		config.CurrentConfig.Bootstrap = &config.BootstrapCreds{}
	}
	config.CurrentConfig.Bootstrap.RegistrationKey = key
	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		return fmt.Errorf("save config with registration key: %w", err)
	}

	if !agent.NeedsRegistration() {
		log.Printf("Agent already registered: %s", config.CurrentConfig.Agent.AgentId)
		return nil
	}

	agent.DoRegistration()
	if agent.NeedsRegistration() {
		return fmt.Errorf("agent registration did not complete")
	}

	return nil
}

func doValidate(configPath string) error {
	cfg, err := config.LoadConfig(configPath, Version())
	if err != nil {
		return err
	}

	apiBase := strings.TrimSpace(cfg.ApiBase)
	if apiBase == "" {
		return fmt.Errorf("config missing api_base")
	}
	if _, err := url.ParseRequestURI(apiBase); err != nil {
		return fmt.Errorf("invalid api_base %q: %w", apiBase, err)
	}

	if cfg.Auth == nil || cfg.Auth.KeyPair == nil {
		return fmt.Errorf("config missing auth keypair")
	}
	if _, err := cfg.Auth.KeyPair.DecodePrivateKey(); err != nil {
		return fmt.Errorf("invalid auth private key: %w", err)
	}

	hasAgent := cfg.Agent != nil && strings.TrimSpace(cfg.Agent.AgentId) != ""
	hasBootstrap := cfg.Bootstrap != nil && strings.TrimSpace(cfg.Bootstrap.RegistrationKey) != ""
	if !hasAgent && !hasBootstrap {
		return fmt.Errorf("config must contain either agent credentials or a bootstrap registration key")
	}

	log.Printf("Validation successful for %s", configPath)
	return nil
}

func versionCmd() {
	fmt.Printf("certkit-agent %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built: %s\n", date)
	fmt.Printf("go: %s\n", runtime.Version())
	fmt.Printf("os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
}
