//go:build !windows

package agent

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/certkit-io/certkit-agent/config"
)

func runUpdateCommand(cfg config.CertificateConfiguration) (output string, err error) {
	if strings.TrimSpace(cfg.UpdateCmd) == "" {
		return "", nil
	}

	log.Printf("Running update command: '%s'", cfg.UpdateCmd)

	cmd := exec.Command("sh", "-c", cfg.UpdateCmd)

	combinedOutput, err := cmd.CombinedOutput()
	if len(combinedOutput) > 0 {
		log.Printf("Update command output for '%s':\n%s", cfg.UpdateCmd, string(combinedOutput))
	}
	if err != nil {
		return string(combinedOutput), fmt.Errorf("Update command failed: \n%w\n%s", err, string(combinedOutput))
	}

	return string(combinedOutput), nil
}
