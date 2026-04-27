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
