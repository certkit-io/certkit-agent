//go:build windows

package agent

import (
	"fmt"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func runUpdateCommand(cfg config.CertificateConfiguration, vars []utils.UpdateVariable) (output string, err error) {
	if strings.TrimSpace(cfg.UpdateCmd) == "" {
		return "", nil
	}

	script, appliedVarCount := utils.BuildPowerShellScript(cfg.UpdateCmd, vars, "")
	if dropped := len(vars) - appliedVarCount; dropped > 0 {
		log.Printf("Dropped %d update variables with invalid names for config %s", dropped, cfg.Id)
	}

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
