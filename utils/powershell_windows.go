//go:build windows

package utils

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// utf8OutputPrefix is prepended to every script handed to powershell.exe.  Switching the console output
// encoding up front makes PowerShell, and the native commands it runs, emit UTF-8 instead.
const utf8OutputPrefix = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"

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
			"-Command", utf8OutputPrefix+input,
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
// The script gets at most timeout to run. If it is still running then, it is
// killed along with every process it started, and whatever it printed up to
// that point is returned alongside the timeout error. StopRunningScripts kills
// it the same way. If the agent process exits while the script is running,
// Windows kills the script and everything it started.
//
// Other call sites that build inline scripts from trusted, escaped values
// should keep using RunPowerShell.
func RunPowerShellViaStdin(scriptContent string, timeout time.Duration) (string, error) {
	if agentStopping.Err() != nil {
		log.Printf("Not starting PowerShell script because the agent service is stopping")
		return "", errors.New("not started because the agent service was stopping")
	}

	encodedScript := base64.StdEncoding.EncodeToString([]byte(scriptContent))

	// Fixed bootstrapper — no user data interpolated here. Edit with care.
	bootstrap := utf8OutputPrefix + `try { $encoded = [Console]::In.ReadToEnd(); $script = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded)); & ([scriptblock]::Create($script)); exit 0 } catch { [Console]::Error.WriteLine(($_ | Out-String)); exit 1 }`

	// powershell.exe runs inside a job object so a timeout can kill the whole
	// process tree. Killing powershell.exe alone would leave anything it started
	// (ssh.exe, python.exe, ...) running and holding the output pipe open.
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return "", fmt.Errorf("create job object: %w", err)
	}
	// If the agent process exits while the script is running, Windows closes the
	// job and kills everything in it, instead of leaving the script running with
	// nothing left to stop it. Once the script is done the setting is cleared,
	// so processes it deliberately left running in the background keep running,
	// as they always have.
	if err := setKillOnJobClose(job, true); err != nil {
		log.Printf("Warning: could not set the job object to kill the script if the agent exits: %v", err)
	}
	defer func() {
		if err := setKillOnJobClose(job, false); err != nil {
			log.Printf("Warning: could not clear kill-on-close on the job object: %v", err)
		}
		windows.CloseHandle(job)
	}()

	ctx, cancel := context.WithTimeout(agentStopping, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx,
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", bootstrap,
	)
	cmd.Stdin = strings.NewReader(encodedScript)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Cancel = func() error {
		return windows.TerminateJobObject(job, 1)
	}
	// Once the script exits or is killed, wait at most a minute more for its
	// output, in case something it started is still holding the pipe open.
	cmd.WaitDelay = time.Minute

	if err := cmd.Start(); err != nil {
		return "", err
	}
	// powershell.exe needs hundreds of milliseconds to load before the script
	// can start anything, so nothing escapes the job before this runs. If it
	// fails anyway, a timeout still kills powershell.exe once WaitDelay passes.
	if err := assignProcessToJob(job, cmd.Process.Pid); err != nil {
		log.Printf("Warning: could not add powershell.exe to a job object; a timeout will only stop powershell.exe itself: %v", err)
	}

	err = cmd.Wait()
	output := strings.TrimSpace(out.String())
	if errors.Is(err, exec.ErrWaitDelay) {
		// The script finished successfully; something it started in the
		// background is still holding the output pipe open.
		return output, nil
	}
	if err != nil && agentStopping.Err() != nil {
		log.Printf("PowerShell script interrupted because the agent service is stopping; stopped it and every process it started")
		return output, errors.New("interrupted because the agent service was stopping; stopped the script and every process it started")
	}
	if err != nil && ctx.Err() != nil {
		log.Printf("PowerShell script timed out after %s; stopped it and every process it started", timeout)
		return output, fmt.Errorf("timed out after %s; stopped the script and every process it started", timeout)
	}
	return output, err
}

// assignProcessToJob adds a running process to a job object. Processes it
// starts from then on are created inside the job too.
func assignProcessToJob(job windows.Handle, pid int) error {
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(process)
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		return fmt.Errorf("assign process %d to job: %w", pid, err)
	}
	return nil
}

// setKillOnJobClose turns on or off killing every process in a job when the
// last handle to the job is closed, which also happens when the process that
// holds the handle exits.
func setKillOnJobClose(job windows.Handle, kill bool) error {
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if kill {
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	}
	_, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	return err
}

// agentStopping is canceled by StopRunningScripts. Every script
// RunPowerShellViaStdin runs is tied to it.
var agentStopping, markAgentStopping = context.WithCancel(context.Background())

// StopRunningScripts is called when the agent service is stopping. It kills
// any script RunPowerShellViaStdin is running, along with every process the
// script started, and makes later calls fail without starting a script. The
// callers get an error back, so a deploy cut short this way is recorded as
// failed instead of holding up the stop.
func StopRunningScripts() {
	markAgentStopping()
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
