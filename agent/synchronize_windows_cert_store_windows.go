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
			out, err := runWindowsCertStoreUpdateCmd(thumbprint, cfg.UpdateCmd, getUpdateVariables(cfg.Id))
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

func runWindowsCertStoreUpdateCmd(thumbprint, updateCmd string, vars []api.UpdateVariable) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for update command")
	}

	script, appliedVarCount := buildWindowsCertStoreScript(thumbprint, updateCmd, vars)

	log.Printf("Running windows-cert-store update command (vars=%d)", appliedVarCount)
	out, err := utils.RunPowerShellViaStdin(script)
	logPowerShellOutput("runWindowsCertStoreUpdateCmd", out)
	return out, err
}

// buildWindowsCertStoreScript composes the PowerShell script for the
// windows-cert-store config type:
//  1. $ErrorActionPreference = 'Stop' fail-fast preamble.
//  2. One `$NAME = 'VALUE'` per validated user variable.
//  3. Cert-load convenience block exposing $thumbprint and $certificate.
//  4. The user's update_cmd verbatim.
//
// Variables go before the cert-load block so the briefing's "shoved at the
// top" intent is honored; the cert convenience is system-injected and sits
// just before the user command so the user can reference both.
func buildWindowsCertStoreScript(thumbprint, updateCmd string, vars []api.UpdateVariable) (string, int) {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")

	appliedVarCount := 0
	for _, v := range vars {
		if !isValidVariableName(v.Name) {
			log.Printf("Skipping update variable with invalid name for windows-cert-store update")
			continue
		}
		b.WriteString("$")
		b.WriteString(v.Name)
		b.WriteString(" = '")
		b.WriteString(escapePowerShellString(v.Value))
		b.WriteString("'\n")
		appliedVarCount++
	}

	fmt.Fprintf(&b, "$thumbprint = '%s'\n", escapePowerShellString(thumbprint))
	b.WriteString("$certificate = Get-Item \"Cert:\\LocalMachine\\My\\$thumbprint\" -ErrorAction Stop\n")

	b.WriteString(updateCmd)
	if !strings.HasSuffix(updateCmd, "\n") {
		b.WriteString("\n")
	}

	return b.String(), appliedVarCount
}
