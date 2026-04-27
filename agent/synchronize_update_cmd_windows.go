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

func runUpdateCommand(cfg config.CertificateConfiguration, vars []api.UpdateVariable) (output string, err error) {
	if strings.TrimSpace(cfg.UpdateCmd) == "" {
		return "", nil
	}

	script, appliedVarCount := buildPowerShellScript(cfg.UpdateCmd, vars, cfg.Id)

	log.Printf("Running update command for config %s (vars=%d)", cfg.Id, appliedVarCount)

	out, err := utils.RunPowerShellViaStdin(script)
	if out != "" {
		log.Printf("Update command output for config %s:\n%s", cfg.Id, out)
	}
	if err != nil {
		return out, fmt.Errorf("Update command failed: \n%w\n%s", err, out)
	}

	return out, nil
}

// buildPowerShellScript composes the script piped to powershell.exe via stdin:
// the $ErrorActionPreference fail-fast preamble, then one `$NAME = 'VALUE'`
// per validated variable, then the user's update_cmd verbatim. The returned
// int is the count of variables actually injected (invalid names are skipped).
// Pure helper for testability.
func buildPowerShellScript(updateCmd string, vars []api.UpdateVariable, configID string) (string, int) {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")

	appliedVarCount := 0
	for _, v := range vars {
		if !isValidVariableName(v.Name) {
			log.Printf("Skipping update variable with invalid name for config %s", configID)
			continue
		}
		b.WriteString("$")
		b.WriteString(v.Name)
		b.WriteString(" = '")
		b.WriteString(escapePowerShellString(v.Value))
		b.WriteString("'\n")
		appliedVarCount++
	}

	b.WriteString(updateCmd)
	if !strings.HasSuffix(updateCmd, "\n") {
		b.WriteString("\n")
	}

	return b.String(), appliedVarCount
}
