//go:build windows

package utils

import (
	"strings"
	"testing"
)

// End-to-end tests that build a script the way runUpdateCommand does and run
// it through powershell.exe to confirm the wrapper genuinely propagates
// errors and supports realistic multi-line user commands.

type scriptScenario struct {
	name       string
	userCmd    string
	vars       []UpdateVariable
	sysInject  string
	wantErr    bool     // true if RunPowerShellViaStdin must return a non-nil error
	wantOut    []string // substrings that MUST appear in combined output
	wantNotOut []string // substrings that must NOT appear
}

func runScenario(t *testing.T, s scriptScenario) {
	t.Helper()
	script, _ := BuildPowerShellScript(s.userCmd, s.vars, s.sysInject)
	out, err := RunPowerShellViaStdin(script)
	if s.wantErr && err == nil {
		t.Fatalf("expected error, got success.\nout=%s", out)
	}
	if !s.wantErr && err != nil {
		t.Fatalf("expected success, got error=%v\nout=%s", err, out)
	}
	for _, want := range s.wantOut {
		if !strings.Contains(out, want) {
			t.Errorf("expected output to contain %q\nout=%s", want, out)
		}
	}
	for _, notWant := range s.wantNotOut {
		if strings.Contains(out, notWant) {
			t.Errorf("expected output NOT to contain %q\nout=%s", notWant, out)
		}
	}
}

// --- Success paths -----------------------------------------------------------

func TestE2E_MultilineIfElse(t *testing.T) {
	runScenario(t, scriptScenario{
		name: "if/else block spanning lines",
		userCmd: `$x = 5
if ($x -gt 3) {
    Write-Host "big"
} else {
    Write-Host "small"
}`,
		wantOut:    []string{"big"},
		wantNotOut: []string{"small"},
	})
}

func TestE2E_MultilineForeach(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `foreach ($i in 1..3) {
    Write-Host "iter-$i"
}`,
		wantOut: []string{"iter-1", "iter-2", "iter-3"},
	})
}

func TestE2E_FunctionDefinitionAndCall(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `function Greet($who) {
    Write-Host "hello $who"
}
Greet "world"
Greet "again"`,
		wantOut: []string{"hello world", "hello again"},
	})
}

func TestE2E_HereStringMultiline(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `$msg = @"
line one
line two
line three
"@
Write-Host $msg`,
		wantOut: []string{"line one", "line two", "line three"},
	})
}

func TestE2E_PipelineSuccess(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `1..3 |
  ForEach-Object { "n=$_" } |
  Sort-Object`,
		wantOut: []string{"n=1", "n=2", "n=3"},
	})
}

func TestE2E_TryCatchInsideUserScript(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `try {
    Get-Item "C:\does-not-exist-xyz"
} catch {
    Write-Host "user-handled: $($_.Exception.Message)"
}
Write-Host "after-catch"`,
		wantOut: []string{"user-handled:", "after-catch"},
	})
}

// --- Variable injection ------------------------------------------------------

func TestE2E_VariableUsedInsideMultilineBlock(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `if ($PW.Length -gt 0) {
    Write-Host "len=$($PW.Length)"
    Write-Host "val=$PW"
}`,
		vars:    []UpdateVariable{{Name: "PW", Value: "secret123"}},
		wantOut: []string{"len=9", "val=secret123"},
	})
}

func TestE2E_VariableWithSingleQuote(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Write-Host "got=$PW"`,
		vars:    []UpdateVariable{{Name: "PW", Value: "it's a secret"}},
		wantOut: []string{"got=it's a secret"},
	})
}

func TestE2E_SystemInjectedVarsAccessible(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd:   `Write-Host "thumb=$thumbprint cert=$certInfo"`,
		sysInject: "$thumbprint = 'ABCDEF'\n$certInfo = 'fake-cert'\n",
		wantOut:   []string{"thumb=ABCDEF cert=fake-cert"},
	})
}

// --- Error propagation -------------------------------------------------------

func TestE2E_CmdletErrorEarlyHalts(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Get-Item "C:\does-not-exist-xyz-abc"
Write-Host "should-not-reach"`,
		wantErr:    true,
		wantNotOut: []string{"should-not-reach"},
	})
}

func TestE2E_CmdletErrorMidMultilineHalts(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Write-Host "before"
foreach ($i in 1..5) {
    if ($i -eq 3) {
        Get-Item "C:\does-not-exist-xyz"
    }
    Write-Host "iter-$i"
}
Write-Host "after-loop"`,
		wantErr:    true,
		wantOut:    []string{"before", "iter-1", "iter-2"},
		wantNotOut: []string{"iter-3", "iter-4", "iter-5", "after-loop"},
	})
}

func TestE2E_ThrowFromUserScriptPropagates(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Write-Host "starting"
throw "user-says-no"
Write-Host "should-not-reach"`,
		wantErr:    true,
		wantOut:    []string{"starting", "user-says-no"},
		wantNotOut: []string{"should-not-reach"},
	})
}

func TestE2E_NonTerminatingErrorBecomesTerminating(t *testing.T) {
	// Without $ErrorActionPreference='Stop', Get-ChildItem on a missing path
	// would only emit a non-terminating error and execution would continue.
	// The preamble in BuildPowerShellScript flips it to terminating.
	runScenario(t, scriptScenario{
		userCmd: `Get-ChildItem "C:\does-not-exist-xyz"
Write-Host "should-not-reach"`,
		wantErr:    true,
		wantNotOut: []string{"should-not-reach"},
	})
}

func TestE2E_NativeCommandFailureAtEnd(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Write-Host "before"
cmd /c "exit 13"`,
		wantErr: true,
		wantOut: []string{"before", "Command exited with code 13"},
	})
}

// Native commands don't auto-halt mid-script — but a user who explicitly
// checks $LASTEXITCODE can throw to abort. Confirm that pattern works.
func TestE2E_NativeCommandFailureMidScriptWithCheck(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Write-Host "before"
cmd /c "exit 4"
if ($LASTEXITCODE -ne 0) { throw "native step failed: $LASTEXITCODE" }
Write-Host "should-not-reach"`,
		wantErr:    true,
		wantOut:    []string{"before", "native step failed: 4"},
		wantNotOut: []string{"should-not-reach"},
	})
}

// Without an explicit $LASTEXITCODE check, a mid-script native failure does
// NOT halt — execution continues until the trailing check at the end. This
// test documents that behavior so future changes don't regress it silently.
func TestE2E_NativeCommandFailureMidScriptWithoutCheck(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Write-Host "before"
cmd /c "exit 5"
Write-Host "still-running"
cmd /c "exit 0"`, // resets $LASTEXITCODE; trailing check sees 0 → success
		wantErr: false,
		wantOut: []string{"before", "still-running"},
	})
}

// --- Edge cases --------------------------------------------------------------

func TestE2E_MultilineWithComments(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `# leading comment
Write-Host "one"
# mid comment
Write-Host "two" # trailing
<#
   block
   comment
#>
Write-Host "three"`,
		wantOut: []string{"one", "two", "three"},
	})
}

func TestE2E_StdoutAndStderrBothCaptured(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Write-Host "stdout-line"
[Console]::Error.WriteLine("stderr-line")`,
		wantOut: []string{"stdout-line", "stderr-line"},
	})
}

func TestE2E_OutputOrderingPreserved(t *testing.T) {
	runScenario(t, scriptScenario{
		userCmd: `Write-Host "A"
Write-Host "B"
Write-Host "C"`,
		wantOut: []string{"A", "B", "C"},
	})
	// Also assert ordering explicitly.
	script, _ := BuildPowerShellScript("Write-Host A\nWrite-Host B\nWrite-Host C", nil, "")
	out, err := RunPowerShellViaStdin(script)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a, b, c := strings.Index(out, "A"), strings.Index(out, "B"), strings.Index(out, "C")
	if !(a >= 0 && a < b && b < c) {
		t.Fatalf("expected A,B,C in order. out=%s", out)
	}
}

func TestE2E_EmptyUserCmd(t *testing.T) {
	// runUpdateCommand short-circuits empty input upstream, but the builder
	// itself should still produce a runnable script if called with "".
	runScenario(t, scriptScenario{
		userCmd: "",
		wantErr: false,
	})
}

func TestE2E_ScriptUsesVariableThenSystemInjectedVar(t *testing.T) {
	// Realistic windows-cert-store flow: user references both their own
	// variable and the system-injected $thumbprint inside a multi-line block.
	runScenario(t, scriptScenario{
		userCmd: `if ($thumbprint -and $TARGET_SERVICE) {
    Write-Host "binding $thumbprint to $TARGET_SERVICE"
} else {
    throw "missing values"
}`,
		vars:      []UpdateVariable{{Name: "TARGET_SERVICE", Value: "MyApp"}},
		sysInject: "$thumbprint = 'ABC123'\n",
		wantOut:   []string{"binding ABC123 to MyApp"},
	})
}
