package agent

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

const (
	caStatusTrusted       = "TRUSTED"
	caStatusInstalled     = "INSTALLED"
	caStatusNotTrusted    = "NOT_TRUSTED"
	caStatusErrorInstall  = "ERROR_INSTALL"
	caStatusUnsupportedOS = "UNSUPPORTED_OS"
)

const (
	privateCaRecheckInterval  = 24 * time.Hour
	privateCaMessageMaxLength = 500
)

// applyPrivateCAUpdates applies the server's private CA list as the
// authoritative set: entries not present are dropped from config (the root is
// never uninstalled from the OS trust store). Status fields are preserved for
// entries whose root is unchanged; a changed root or auto_install flag clears
// LastVerified so the CA is re-checked on the next synchronization.
func applyPrivateCAUpdates(incoming []api.PollResponsePrivateCA) {
	previous := config.CurrentConfig.PrivateCAs

	previousByID := make(map[string]config.PrivateCAConfig, len(previous))
	for _, ca := range previous {
		if ca.Id != "" {
			previousByID[ca.Id] = ca
		}
	}

	updated := make([]config.PrivateCAConfig, 0, len(incoming))
	changed := false
	for _, in := range incoming {
		if in.Id == "" {
			continue
		}

		entry := config.PrivateCAConfig{
			Id:          in.Id,
			Name:        in.Name,
			RootCAPEM:   in.RootCAPEM,
			RootSHA256:  in.RootSHA256,
			AutoInstall: in.AutoInstall,
		}

		prev, existed := previousByID[in.Id]
		if existed && strings.EqualFold(prev.RootSHA256, in.RootSHA256) {
			entry.LastStatus = prev.LastStatus
			entry.InstalledByAgent = prev.InstalledByAgent
			if prev.AutoInstall == in.AutoInstall {
				entry.LastVerified = prev.LastVerified
			}
		}

		if !existed {
			log.Printf("Private CA %s (%s) added by server", in.Id, in.Name)
			changed = true
		} else if prev.Name != in.Name ||
			prev.RootCAPEM != in.RootCAPEM ||
			!strings.EqualFold(prev.RootSHA256, in.RootSHA256) ||
			prev.AutoInstall != in.AutoInstall {
			changed = true
		}

		updated = append(updated, entry)
	}

	for _, prev := range previous {
		stillManaged := false
		for _, ca := range updated {
			if ca.Id == prev.Id {
				stillManaged = true
				break
			}
		}
		if !stillManaged {
			log.Printf("Private CA %s (%s) no longer managed by server; removing from config (root is left in the OS trust store)", prev.Id, prev.Name)
			changed = true
		}
	}

	if !changed {
		return
	}

	config.CurrentConfig.PrivateCAs = updated
	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		log.Printf("Error saving config after private CA update: %v", err)
	}
}

func SynchronizePrivateCAs() []api.AgentPrivateCaStatusUpdate {
	statuses := make([]api.AgentPrivateCaStatusUpdate, 0, len(config.CurrentConfig.PrivateCAs))
	configDirty := false
	now := time.Now().UTC()

	for i := range config.CurrentConfig.PrivateCAs {
		ca := &config.CurrentConfig.PrivateCAs[i]

		if !shouldCheckPrivateCa(*ca, now) {
			continue
		}

		newStatus, message := checkPrivateCa(ca)

		verifiedAt := now
		ca.LastVerified = &verifiedAt
		configDirty = true

		if newStatus != ca.LastStatus {
			statuses = append(statuses, api.AgentPrivateCaStatusUpdate{
				CaId:             ca.Id,
				Status:           newStatus,
				InstalledByAgent: ca.InstalledByAgent,
				Message:          message,
				LastStatusDate:   now,
			})
			ca.LastStatus = newStatus
		}
	}

	if configDirty {
		if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
			reportAgentError(err, "", "")
		}
	}

	return statuses
}

func shouldCheckPrivateCa(ca config.PrivateCAConfig, now time.Time) bool {
	if ca.LastStatus == caStatusErrorInstall {
		return true
	}
	if ca.LastVerified == nil {
		return true
	}
	return now.Sub(*ca.LastVerified) >= privateCaRecheckInterval
}

func checkPrivateCa(ca *config.PrivateCAConfig) (status string, message string) {
	if reason := privateCaTrustStoreUnsupportedReason(); reason != "" {
		return caStatusUnsupportedOS, truncatePrivateCaMessage(reason)
	}

	trusted, err := isRootCaTrusted(*ca)
	if err != nil {
		log.Printf("Error checking trust store for private CA %s: %v", ca.Id, err)
		return caStatusErrorInstall, truncatePrivateCaMessage(fmt.Sprintf("Error checking trust store: %v", err))
	}
	if trusted {
		return caStatusTrusted, ""
	}
	if !ca.AutoInstall {
		return caStatusNotTrusted, ""
	}

	log.Printf("Installing private CA root %s (%s) into the OS trust store", ca.Id, ca.Name)
	if err := installRootCa(*ca); err != nil {
		log.Printf("Error installing private CA root %s: %v", ca.Id, err)
		return caStatusErrorInstall, truncatePrivateCaMessage(fmt.Sprintf("Error installing root CA: %v", err))
	}

	ca.InstalledByAgent = true
	log.Printf("Installed private CA root %s (%s) into the OS trust store", ca.Id, ca.Name)
	return caStatusInstalled, ""
}

func truncatePrivateCaMessage(message string) string {
	if len(message) <= privateCaMessageMaxLength {
		return message
	}
	return message[:privateCaMessageMaxLength]
}
