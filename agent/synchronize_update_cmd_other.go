//go:build !windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func runUpdateCommand(cfg config.CertificateConfiguration, vars []utils.UpdateVariable) (output string, err error) {
	if strings.TrimSpace(cfg.UpdateCmd) == "" {
		return "", nil
	}

	interpreter, preamble := pickShellPreamble()
	script, appliedVarCount := buildShellScript(preamble, cfg.UpdateCmd, vars)
	if dropped := len(vars) - appliedVarCount; dropped > 0 {
		log.Printf("Dropped %d update variables with invalid names for config %s", dropped, cfg.Id)
	}

	log.Printf("Running update command for config %s (interpreter=%s, vars=%d)", cfg.Id, interpreter, appliedVarCount)

	ctx, cancel := context.WithTimeout(context.Background(), updateCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, interpreter, "-s")
	cmd.Stdin = strings.NewReader(script)
	// The shell leads its own process group so a timeout can kill everything
	// the command started (ssh, curl, ...), not just the shell.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	// Once the command exits or is killed, wait at most a minute more for its
	// output, in case something it started is still holding the pipe open.
	cmd.WaitDelay = time.Minute

	combinedOutput, err := cmd.CombinedOutput()
	if len(combinedOutput) > 0 {
		log.Printf("Update command output for config %s:\n%s", cfg.Id, string(combinedOutput))
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		// The command finished successfully; something it started in the
		// background is still holding the output pipe open.
		err = nil
	}
	if err != nil && ctx.Err() != nil {
		log.Printf("Update command for config %s timed out after %s; stopped it and every process it started", cfg.Id, updateCommandTimeout)
		return string(combinedOutput), fmt.Errorf("update command failed: timed out after %s; stopped the script and every process it started", updateCommandTimeout)
	}
	if err != nil {
		return string(combinedOutput), fmt.Errorf("update command failed: %w", err)
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
// verbatim. Variables whose names don't match [A-Za-z_][A-Za-z0-9_]* are
// silently skipped — defense in depth against shell injection via the
// assignment line. Returns the full script and the count of variables
// actually injected.
func buildShellScript(preamble, updateCmd string, vars []utils.UpdateVariable) (string, int) {
	var b strings.Builder
	b.WriteString(preamble)

	appliedVarCount := 0
	for _, v := range vars {
		if !utils.IsValidVariableName(v.Name) {
			continue
		}
		fmt.Fprintf(&b, "export %s='%s'\n", v.Name, escapeShellSingleQuoted(v.Value))
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
