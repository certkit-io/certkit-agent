package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	agentCrypto "github.com/certkit-io/certkit-agent/crypto"
	"github.com/certkit-io/certkit-agent/utils"
)

var CurrentConfig Config
var CurrentPath string

type Config struct {
	ApiBase                   string                     `json:"api_base"`
	Bootstrap                 *BootstrapCreds            `json:"bootstrap,omitempty"`
	Agent                     *AgentCreds                `json:"agent,omitempty"`
	CertificateConfigurations []CertificateConfiguration `json:"certificate_configurations,omitempty"`
	InventorySent             bool                       `json:"inventory_sent,omitempty"`
	Auth                      *AuthCreds                 `json:"auth,omitempty"`
	Version                   VersionInfo                `json:"-"`
}

type BootstrapCreds struct {
	RegistrationKey string `json:"registration_key"`
}

type AgentCreds struct {
	AgentId string `json:"agent_id"`
}

type AuthCreds struct {
	KeyPair *agentCrypto.KeyPair `json:"key_pair"`
}

type CertificateConfiguration struct {
	Id                          string     `json:"config_id"`
	CertificateId               string     `json:"certificate_id,omitempty"`
	LastConfigurationUpdateDate *time.Time `json:"last_configuration_update_date,omitempty"`
	LastCertificateUpdateDate   *time.Time `json:"last_certificate_update_date,omitempty"`
	LatestCertificateSha1       string     `json:"latest_certificate_sha1,omitempty"`
	LastStatus                  string     `json:"last_status,omitempty"`
	PemDestination              string     `json:"pem_destination,omitempty"`
	KeyDestination              string     `json:"key_destination,omitempty"`
	ChainDestination            string     `json:"chain_destination,omitempty"`
	OwnerUser                   string     `json:"owner_user,omitempty"`
	OwnerGroup                  string     `json:"owner_group,omitempty"`
	FilePermissions             string     `json:"file_permissions,omitempty"`
	UpdateCmd                   string     `json:"update_cmd,omitempty"`
	Name                        string     `json:"name,omitempty"`
	AllInOne                    bool       `json:"all_in_one,omitempty"`
	IsPfx                       bool       `json:"is_pfx"`
	ConfigType                  string     `json:"config_type"`
}

type VersionInfo struct {
	Version string
	Commit  string
	Date    string
}

const (
	defaultAPIBase = "https://app.certkit.io"
)

func CreateInitialConfig(path string) error {
	registrationKey := os.Getenv("REGISTRATION_KEY")

	if registrationKey == "" {
		return fmt.Errorf("REGISTRATION_KEY is required for first install")
	}

	apiBase := os.Getenv("CERTKIT_API_BASE")
	if apiBase == "" {
		apiBase = defaultAPIBase
	}

	cfg := &Config{
		ApiBase: apiBase,
		Bootstrap: &BootstrapCreds{
			RegistrationKey: registrationKey,
		},
		Agent: nil,
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	return SaveConfig(cfg, path)
}

func SaveConfig(cfg *Config, path string) error {
	configBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	configBytes = append(configBytes, '\n')

	return utils.WriteFileAtomic(path, configBytes, 0o600)
}

func LoadConfig(path string, version VersionInfo) (Config, error) {
	var cfg Config

	if path == "" {
		return cfg, fmt.Errorf("config path is empty")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, fmt.Errorf("config file does not exist: %s", path)
		}
		return cfg, fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	if len(bytes.TrimSpace(b)) == 0 {
		return cfg, fmt.Errorf("config file %s is empty", path)
	}

	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// // Exactly one of Bootstrap or Agent should be present
	// if cfg.Bootstrap == nil && cfg.Agent == nil {
	// 	return cfg, fmt.Errorf(
	// 		"config %s: either bootstrap or agent credentials must be present",
	// 		path,
	// 	)
	// }

	if !hasKeyPair(&cfg) {
		log.Print("Generating new keypair...")
		keyPair, _ := agentCrypto.CreateNewKeyPair()
		cfg.Auth = &AuthCreds{
			KeyPair: keyPair,
		}
		SaveConfig(&cfg, path)
	}

	cfg.Version = version

	CurrentConfig = cfg
	CurrentPath = path

	return cfg, nil
}

func hasKeyPair(cfg *Config) bool {
	if cfg == nil {
		return false
	}
	if cfg.Auth == nil {
		return false
	}
	if cfg.Auth.KeyPair == nil {
		return false
	}
	if cfg.Auth.KeyPair.PublicKey == "" || cfg.Auth.KeyPair.PrivateKey == "" {
		return false
	}
	return true
}
