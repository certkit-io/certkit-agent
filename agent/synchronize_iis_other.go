//go:build !windows

package agent

import (
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

func synchronizeIISCertificate(cfg config.CertificateConfiguration, _ bool) api.AgentConfigStatusUpdate {
	status := api.AgentConfigStatusUpdate{
		ConfigId:       cfg.Id,
		LastStatusDate: time.Now().UTC(),
		Status:         statusErrorGeneral,
		Message:        "IIS synchronization is only supported on Windows",
	}
	return status
}
