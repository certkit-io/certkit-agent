//go:build windows

package agent

import (
	"fmt"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func runUpdateCommand(cfg config.CertificateConfiguration) (output string, err error) {
	if strings.TrimSpace(cfg.UpdateCmd) == "" {
		return "", nil
	}

	log.Printf("Running update command: '%s'", cfg.UpdateCmd)

	out, err := utils.RunPowerShell(cfg.UpdateCmd)
	if out != "" {
		log.Printf("Update command output for '%s':\n%s", cfg.UpdateCmd, out)
	}
	if err != nil {
		return out, fmt.Errorf("Update command failed: \n%w\n%s", err, out)
	}

	return out, nil
}
