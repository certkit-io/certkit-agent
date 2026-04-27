//go:build windows

package utils

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func RunPowerShell(input string) (string, error) {
	input = strings.TrimSpace(input)
	isScriptFile := false
	if strings.HasSuffix(strings.ToLower(input), ".ps1") {
		if fi, err := os.Stat(input); err == nil && !fi.IsDir() {
			isScriptFile = true
		}
	}

	var cmd *exec.Cmd
	if isScriptFile {
		cmd = exec.Command(
			"powershell.exe",
			"-NoProfile",
			"-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-File", input,
		)
	} else {
		cmd = exec.Command(
			"powershell.exe",
			"-NoProfile",
			"-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-Command", input,
		)
	}

	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output != "" {
			return output, fmt.Errorf("%w: %s", err, output)
		}
		return "", err
	}
	return output, nil
}

// RunPowerShellViaStdin executes the given script content by piping it to
// powershell.exe via stdin. Use this when the script contains user-supplied
// templates plus secret variable assignments — stdin keeps secrets off the
// command line where Win32_Process would expose them to other processes.
//
// Other call sites that build inline scripts from trusted, escaped values
// should keep using RunPowerShell.
func RunPowerShellViaStdin(scriptContent string) (string, error) {
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", "-",
	)
	cmd.Stdin = strings.NewReader(scriptContent)

	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if err != nil {
		if output != "" {
			return output, fmt.Errorf("%w: %s", err, output)
		}
		return "", err
	}
	return output, nil
}

// BuildPowerShellScript composes a script for piping to RunPowerShellViaStdin:
//  1. $ErrorActionPreference = 'Stop' fail-fast preamble.
//  2. One $NAME = 'VALUE' line per validated user variable. Variables whose
//     names don't match [A-Za-z_][A-Za-z0-9_]* are silently skipped — defense
//     in depth against shell injection via the assignment line.
//  3. Optional system-injected lines (e.g. the windows-cert-store cert load
//     block exposing $thumbprint and $certificate). Pass "" if not needed.
//  4. The user's command verbatim, with a trailing newline if missing.
//
// Returns the full script and the count of variables actually injected. The
// caller can compare this to len(vars) to detect dropped invalid names.
func BuildPowerShellScript(userCmd string, vars []UpdateVariable, systemInjected string) (string, int) {
	var b strings.Builder
	b.WriteString("$ErrorActionPreference = 'Stop'\n")

	appliedVarCount := 0
	for _, v := range vars {
		if !IsValidVariableName(v.Name) {
			continue
		}
		fmt.Fprintf(&b, "$%s = '%s'\n", v.Name, escapePowerShellSingleQuoted(v.Value))
		appliedVarCount++
	}

	if systemInjected != "" {
		b.WriteString(systemInjected)
		if !strings.HasSuffix(systemInjected, "\n") {
			b.WriteString("\n")
		}
	}

	b.WriteString(userCmd)
	if !strings.HasSuffix(userCmd, "\n") {
		b.WriteString("\n")
	}

	return b.String(), appliedVarCount
}

// escapePowerShellSingleQuoted escapes a value for inclusion inside a
// single-quoted PowerShell string by doubling each ' to ''.
func escapePowerShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
