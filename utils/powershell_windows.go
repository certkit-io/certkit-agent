//go:build windows

package utils

import (
	"encoding/base64"
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

// RunPowerShellViaStdin executes the given script content via powershell.exe,
// keeping the script (and any embedded secrets) off the command line.
//
// The script content is base64-encoded and piped to stdin. A short, fixed
// bootstrapper passed via -Command reads stdin, decodes it, and invokes the
// result as a script block inside a try/catch. The bootstrapper itself
// contains no user data, so what shows up in Win32_Process.CommandLine is
// only the literal bootstrapper text — secrets stay on stdin.
//
// Why the base64 dance? `powershell.exe -Command -` reads stdin one logical
// statement at a time at the prompt level, so multi-line constructs like
// `try { ... } catch { ... }` and `& { ... }` don't carry over reliably —
// terminating errors silently exit 0. Routing the user script through
// [scriptblock]::Create() runs it under normal script semantics where
// terminating errors propagate up to the bootstrapper's catch.
//
// On error the catch block writes the formatted ErrorRecord directly to
// .NET's Console.Error stream rather than calling Write-Error, which would
// otherwise be wrapped in CLIXML when stderr is redirected to a pipe.
//
// Other call sites that build inline scripts from trusted, escaped values
// should keep using RunPowerShell.
func RunPowerShellViaStdin(scriptContent string) (string, error) {
	encodedScript := base64.StdEncoding.EncodeToString([]byte(scriptContent))

	// Fixed bootstrapper — no user data interpolated here. Edit with care.
	bootstrap := `try { $encoded = [Console]::In.ReadToEnd(); $script = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded)); & ([scriptblock]::Create($script)); exit 0 } catch { [Console]::Error.WriteLine(($_ | Out-String)); exit 1 }`

	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", bootstrap,
	)
	cmd.Stdin = strings.NewReader(encodedScript)

	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// BuildPowerShellScript composes the inner script body that
// RunPowerShellScript will wrap in its try/catch. Layout:
//  1. $ErrorActionPreference = 'Stop' so cmdlet errors are terminating.
//  2. One $NAME = 'VALUE' line per validated user variable. Variables whose
//     names don't match [A-Za-z_][A-Za-z0-9_]* are silently skipped — defense
//     in depth against shell injection via the assignment line.
//  3. Optional system-injected lines (e.g. the windows-cert-store cert load
//     block exposing $thumbprint and $certificate). Pass "" if not needed.
//  4. The user's command verbatim, with a trailing newline if missing.
//  5. A trailing $LASTEXITCODE check that throws if a native command exited
//     non-zero — $ErrorActionPreference doesn't apply to native exes, so we
//     have to convert their failure into a terminating error explicitly.
//
// Terminating errors propagate up to RunPowerShellScript's outer try/catch
// and produce exit 1.
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

	b.WriteString("if ($LASTEXITCODE -ne $null -and $LASTEXITCODE -ne 0) { throw (\"Command exited with code \" + $LASTEXITCODE) }\n")

	return b.String(), appliedVarCount
}

// escapePowerShellSingleQuoted escapes a value for inclusion inside a
// single-quoted PowerShell string by doubling each ' to ”.
func escapePowerShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
