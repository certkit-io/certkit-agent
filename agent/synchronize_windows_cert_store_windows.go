//go:build windows

package agent

import (
	"fmt"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func synchronizeWindowsCertStoreCertificate(cfg config.CertificateConfiguration, configChanged bool) api.AgentConfigStatusUpdate {
	return synchronizeWindowsServiceCert(cfg, configChanged, windowsSyncConfig{
		serviceName: "WindowsCertStore",
		applyFn: func(thumbprint string) (string, error) {
			if strings.TrimSpace(cfg.UpdateCmd) == "" {
				log.Print("No update command configured; skipping update command.")
				return "", nil
			}
			out, err := runWindowsCertStoreUpdateCmd(thumbprint, cfg.UpdateCmd)
			if err != nil {
				return "", err
			}
			if out != "" {
				return fmt.Sprintf("Update command output: \n%s", out), nil
			}
			return "", nil
		},
	})
}

func runWindowsCertStoreUpdateCmd(thumbprint, updateCmd string) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for update command")
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$thumbprint = '%s'
$certificate = Get-Item "Cert:\LocalMachine\My\$thumbprint" -ErrorAction Stop

%s
`, escapePowerShellString(thumbprint), updateCmd)

	log.Printf("Running windows-cert-store update command: '%s'", updateCmd)
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("runWindowsCertStoreUpdateCmd", out)
	return out, err
}
