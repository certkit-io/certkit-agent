package agent

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/inventory"
	"github.com/certkit-io/certkit-agent/selfupdate"
	"github.com/certkit-io/certkit-agent/utils"
)

// ConfigChange describes what changed for a single certificate configuration
// between the previous and incoming poll response.
type ConfigChange struct {
	Changed       bool     // true when the config differs from the previous version
	FormatChanged bool     // true when format-related fields changed (AllInOne, IsPfx, ConfigType, destinations)
	StaleFiles    []string // old file paths that should be removed after writing the new format
}

// updateVarsMap holds per-config update variables in memory only. Values are
// sensitive (passwords, tokens) and must never be persisted to disk or sent
// back to the server. Replaced wholesale on every successful poll so revoked
// credentials don't linger.
var (
	updateVarsMu  sync.Mutex
	updateVarsMap = map[string][]utils.UpdateVariable{}
)

func setUpdateVariables(byID map[string][]utils.UpdateVariable) {
	updateVarsMu.Lock()
	defer updateVarsMu.Unlock()
	if byID == nil {
		updateVarsMap = map[string][]utils.UpdateVariable{}
		return
	}
	updateVarsMap = byID
}

func getUpdateVariables(configID string) []utils.UpdateVariable {
	updateVarsMu.Lock()
	defer updateVarsMu.Unlock()
	return updateVarsMap[configID]
}

func PollAndSync(forceSync bool) {
	configChanges, err := PollForConfiguration(forceSync)
	if err != nil {
		reportAgentError(fmt.Errorf("poll: %w", err), "", "")
		return
	}
	if utils.IsAgentUnauthorized() {
		return
	}

	statuses := SynchronizeCertificates(configChanges, forceSync)
	if len(statuses) > 0 {
		if err := api.UpdateConfigStatus(statuses); err != nil {
			reportAgentError(fmt.Errorf("update status: %w", err), "", "")
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

func PollForConfiguration(forceSync bool) (configChanges map[string]ConfigChange, err error) {
	response, err := api.PollForConfiguration(forceSync)
	if err != nil {
		return nil, err
	}

	isLocked, err := config.IsLocked(config.CurrentPath)
	if err != nil {
		return nil, err
	}

	if response == nil {
		// No changes from the poll response
		return nil, nil
	}

	setUpdateVariables(response.VariablesByConfigId)

	if response.UpdateAvailable != nil {
		selfupdate.SignalUpdateAvailable(
			config.CurrentConfig.Version.Version,
			response.UpdateAvailable.Version,
			response.UpdateAvailable.DownloadURL,
			response.UpdateAvailable.SHA256,
		)
	}

	if response.ForceAutodiscover {
		log.Printf("Auto-discovery requested by server")
		SendInventory()
	}

	if response.Keystore != nil {
		updateKeystoreConfig(response.Keystore)
	} else if config.CurrentConfig.Keystore != nil {
		removeKeystoreConfig()
	}

	if response.LockRequested && !isLocked {
		if err := config.CreateLockFile(config.CurrentPath); err != nil {
			return nil, err
		}
		log.Printf("Lock requested. Agent now locked. Lock file created at %s", config.LockFilePath(config.CurrentPath))

		// Immediately re-poll once so the server sees is_locked=true in the normal loop.
		_, err := api.PollForConfiguration(false)
		if err != nil {
			return nil, err
		}
	}

	if isLocked {
		configChanges = applyLockedConfigUpdates(response.UpdatedCertificateConfigurations)
	} else {
		configChanges = detectChangedConfigs(config.CurrentConfig.CertificateConfigurations, response.UpdatedCertificateConfigurations)
		config.CurrentConfig.CertificateConfigurations = response.UpdatedCertificateConfigurations
	}

	hasChanges := false
	for _, c := range configChanges {
		if c.Changed {
			hasChanges = true
			break
		}
	}

	if !hasChanges {
		return configChanges, nil
	}

	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		return nil, err
	}

	return configChanges, nil
}

func applyLockedConfigUpdates(updated []config.CertificateConfiguration) map[string]ConfigChange {
	changedIDs := make(map[string]ConfigChange)
	if len(updated) == 0 || len(config.CurrentConfig.CertificateConfigurations) == 0 {
		return changedIDs
	}

	byID := make(map[string]config.CertificateConfiguration, len(updated))
	for _, cfg := range updated {
		if cfg.Id == "" {
			continue
		}
		byID[cfg.Id] = cfg
	}

	for i := range config.CurrentConfig.CertificateConfigurations {
		current := &config.CurrentConfig.CertificateConfigurations[i]
		incoming, ok := byID[current.Id]
		if !ok {
			continue
		}

		if current.LatestCertificateSha1 != incoming.LatestCertificateSha1 {
			current.LatestCertificateSha1 = incoming.LatestCertificateSha1
			current.LastCertificateUpdateDate = incoming.LastCertificateUpdateDate
			changedIDs[current.Id] = ConfigChange{Changed: true}
		}
	}

	return changedIDs
}

func detectChangedConfigs(previousConfigurations, incomingConfigurations []config.CertificateConfiguration) map[string]ConfigChange {
	configChanges := make(map[string]ConfigChange)
	if len(incomingConfigurations) == 0 {
		return configChanges
	}

	previousByID := make(map[string]config.CertificateConfiguration, len(previousConfigurations))
	for _, cfg := range previousConfigurations {
		if cfg.Id != "" {
			previousByID[cfg.Id] = cfg
		}
	}

	for _, incoming := range incomingConfigurations {
		if incoming.Id == "" {
			continue
		}
		prev, existed := previousByID[incoming.Id]
		if !existed {
			configChanges[incoming.Id] = ConfigChange{Changed: true}
			continue
		}

		changed := false
		if !timePtrEqual(prev.LastConfigurationUpdateDate, incoming.LastConfigurationUpdateDate) {
			changed = true
		} else if prev.LatestCertificateSha1 != incoming.LatestCertificateSha1 {
			changed = true
		}

		formatChanged := prev.AllInOne != incoming.AllInOne ||
			prev.IsPfx != incoming.IsPfx ||
			!strings.EqualFold(prev.ConfigType, incoming.ConfigType) ||
			prev.PemDestination != incoming.PemDestination ||
			prev.KeyDestination != incoming.KeyDestination ||
			prev.ChainDestination != incoming.ChainDestination

		// All file paths the incoming config will use on disk.
		var incomingPaths []string
		if incoming.PemDestination != "" {
			incomingPaths = append(incomingPaths, incoming.PemDestination)
		}
		if incoming.KeyDestination != "" {
			incomingPaths = append(incomingPaths, incoming.KeyDestination)
		}
		if incoming.ChainDestination != "" {
			incomingPaths = append(incomingPaths, incoming.ChainDestination)
		}

		// All file paths the previous config owned on disk.
		var prevPaths []string
		if !prev.UsesWindowsCertStore() {
			if prev.PemDestination != "" {
				prevPaths = append(prevPaths, prev.PemDestination)
			}
			if !prev.IsJKS() {
				if prev.KeyDestination != "" {
					prevPaths = append(prevPaths, prev.KeyDestination)
				}
				if prev.ChainDestination != "" {
					prevPaths = append(prevPaths, prev.ChainDestination)
				}
			}
		}

		// Stale = previously owned but not in the incoming list.
		var staleFiles []string
		for _, prevPath := range prevPaths {
			if !slices.Contains(incomingPaths, prevPath) {
				staleFiles = append(staleFiles, prevPath)
			}
		}

		configChanges[incoming.Id] = ConfigChange{
			Changed:       changed,
			FormatChanged: formatChanged,
			StaleFiles:    staleFiles,
		}
	}

	return configChanges
}

func timePtrEqual(a, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(*b)
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

func updateKeystoreConfig(ks *config.KeystoreConfig) {
	current := config.CurrentConfig.Keystore
	if current != nil && current.CACertPEM == ks.CACertPEM && current.Host == ks.Host {
		return
	}

	log.Printf("Keystore configuration changed, rebuilding TLS client for %s", ks.Host)
	if err := api.InitKeystoreClient(ks.Host, ks.CACertPEM); err != nil {
		log.Printf("Error initializing keystore TLS client: %v", err)
		return
	}

	config.CurrentConfig.Keystore = &config.KeystoreConfig{
		Host:      ks.Host,
		CACertPEM: ks.CACertPEM,
	}
	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		log.Printf("Error saving keystore config: %v", err)
	}
}

func removeKeystoreConfig() {
	log.Printf("Keystore configuration removed by server, clearing keystore client")
	api.ClearKeystoreClient()
	config.CurrentConfig.Keystore = nil
	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		log.Printf("Error saving config after keystore removal: %v", err)
	}
}

// InitKeystoreFromConfig rebuilds the keystore TLS client from saved config (e.g. on restart).
func InitKeystoreFromConfig() {
	ks := config.CurrentConfig.Keystore
	if ks == nil || ks.CACertPEM == "" || ks.Host == "" {
		return
	}
	if err := api.InitKeystoreClient(ks.Host, ks.CACertPEM); err != nil {
		log.Printf("Warning: failed to initialize keystore client from saved config: %v", err)
	} else {
		log.Printf("Keystore TLS client initialized from saved config for %s", ks.Host)
	}
}

func reportAgentError(err error, configId string, certificateId string) {
	if err == nil {
		return
	}

	// Reporting to the server is fire-and-forget; a failure here is itself
	// usually a network problem already covered by the error we log below.
	_ = api.ReportAgentError(err.Error(), configId, certificateId)
	log.Printf("Error: %v", err)
}
