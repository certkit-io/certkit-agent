//go:build !windows

package agent

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

func runUpdateCommand(cfg config.CertificateConfiguration, vars []api.UpdateVariable) (output string, err error) {
	if strings.TrimSpace(cfg.UpdateCmd) == "" {
		return "", nil
	}

	interpreter, preamble := pickShellPreamble()
	script, appliedVarCount := buildShellScript(preamble, cfg.UpdateCmd, vars, cfg.Id)

	log.Printf("Running update command for config %s (interpreter=%s, vars=%d)", cfg.Id, interpreter, appliedVarCount)

	cmd := exec.Command(interpreter, "-s")
	cmd.Stdin = strings.NewReader(script)

	combinedOutput, err := cmd.CombinedOutput()
	if len(combinedOutput) > 0 {
		log.Printf("Update command output for config %s:\n%s", cfg.Id, string(combinedOutput))
	}
	if err != nil {
		return string(combinedOutput), fmt.Errorf("Update command failed: \n%w\n%s", err, string(combinedOutput))
	}

	return string(combinedOutput), nil
}

func pickShellPreamble() (interpreter, preamble string) {
	if _, err := exec.LookPath("bash"); err == nil {
		return "bash", "set -euo pipefail\n"
	}
	return "sh", "set -eu\n"
}

// buildShellScript composes the script piped to bash/sh: preamble, then one
// `export NAME='VALUE'` per validated variable, then the user's update_cmd
// verbatim. The returned int is the count of variables actually injected
// (invalid names are skipped). Pure helper for testability.
func buildShellScript(preamble, updateCmd string, vars []api.UpdateVariable, configID string) (string, int) {
	var b strings.Builder
	b.WriteString(preamble)

	appliedVarCount := 0
	for _, v := range vars {
		if !isValidVariableName(v.Name) {
			log.Printf("Skipping update variable with invalid name for config %s", configID)
			continue
		}
		b.WriteString("export ")
		b.WriteString(v.Name)
		b.WriteString("='")
		b.WriteString(escapeShellSingleQuoted(v.Value))
		b.WriteString("'\n")
		appliedVarCount++
	}

	b.WriteString(updateCmd)
	if !strings.HasSuffix(updateCmd, "\n") {
		b.WriteString("\n")
	}

	return b.String(), appliedVarCount
}

// escapeShellSingleQuoted escapes a value for inclusion inside a POSIX
// single-quoted string. The only character that ends a single-quoted string
// is another single quote; the standard idiom is to close, emit an escaped
// single quote, then reopen.
func escapeShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", `'\''`)
}
