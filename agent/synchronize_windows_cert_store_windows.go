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

func synchronizeWindowsCertStoreCertificate(cfg config.CertificateConfiguration, change ConfigChange) api.AgentConfigStatusUpdate {
	return synchronizeWindowsServiceCert(cfg, change, windowsSyncConfig{
		serviceName: "WindowsCertStore",
		applyFn: func(thumbprint string) (string, error) {
			if strings.TrimSpace(cfg.UpdateCmd) == "" {
				log.Print("No update command configured; skipping update command.")
				return "", nil
			}
			out, err := runWindowsCertStoreUpdateCmd(cfg.Id, thumbprint, cfg.UpdateCmd, getUpdateVariables(cfg.Id))
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

// runWindowsCertStoreUpdateCmd runs the user's update_cmd for the
// windows-cert-store config type. The system-injected block exposes
// $thumbprint and $certificate so the user's command can reference both.
func runWindowsCertStoreUpdateCmd(configID, thumbprint, updateCmd string, vars []utils.UpdateVariable) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for update command")
	}

	// Windows Cert Store gets a few extra variables
	var windowsCertStoreSpecificScriptInjection strings.Builder
	fmt.Fprintf(&windowsCertStoreSpecificScriptInjection, "$thumbprint = '%s'\n", escapePowerShellString(thumbprint))
	windowsCertStoreSpecificScriptInjection.WriteString("$certificate = Get-Item \"Cert:\\LocalMachine\\My\\$thumbprint\" -ErrorAction Stop\n")

	script, appliedVarCount := utils.BuildPowerShellScript(updateCmd, vars, windowsCertStoreSpecificScriptInjection.String())
	if dropped := len(vars) - appliedVarCount; dropped > 0 {
		log.Printf("Dropped %d update variables with invalid names for config %s", dropped, configID)
	}

	log.Printf("Running windows-cert-store update command for config %s (vars=%d)", configID, appliedVarCount)
	out, err := utils.RunPowerShellViaStdin(script)
	logPowerShellOutput("runWindowsCertStoreUpdateCmd", out)
	return out, err
}
