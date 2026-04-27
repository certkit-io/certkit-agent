//go:build windows

package utils

import (
	"strings"
	"testing"
)

func TestBuildPowerShellScript_NoVarsNoExtras(t *testing.T) {
	script, count := BuildPowerShellScript("Write-Host hi", nil, "")

	if count != 0 {
		t.Fatalf("expected 0 vars applied, got %d", count)
	}
	want := "$ErrorActionPreference = 'Stop'\nWrite-Host hi\n"
	if script != want {
		t.Fatalf("script mismatch:\n got: %q\nwant: %q", script, want)
	}
}

func TestBuildPowerShellScript_PreservesEmbeddedNewlinesInUserCmd(t *testing.T) {
	userCmd := "Write-Host one\nforeach ($i in 1..3) {\n  Write-Host $i\n}"
	script, _ := BuildPowerShellScript(userCmd, nil, "")

	if !strings.Contains(script, userCmd) {
		t.Fatalf("multiline user_cmd was modified during script build:\n%s", script)
	}
	if !strings.HasSuffix(script, "\n") {
		t.Fatalf("script must end with newline:\n%s", script)
	}
}

func TestBuildPowerShellScript_EscapesSingleQuotesInValue(t *testing.T) {
	vars := []UpdateVariable{
		{Name: "PW", Value: "it's a secret"},
	}
	script, count := BuildPowerShellScript("Write-Host $PW", vars, "")

	if count != 1 {
		t.Fatalf("expected 1 var applied, got %d", count)
	}
	// PowerShell single-quoted strings double-up `'` to escape.
	wantLine := "$PW = 'it''s a secret'"
	if !strings.Contains(script, wantLine) {
		t.Fatalf("expected escaped single-quote line %q in script:\n%s", wantLine, script)
	}
}

func TestBuildPowerShellScript_SkipsInvalidVariableNames(t *testing.T) {
	vars := []UpdateVariable{
		{Name: "GOOD", Value: "1"},
		{Name: "BAD NAME", Value: "2"},
		{Name: "9LEAD", Value: "3"},
		{Name: "PW", Value: "4"},
	}
	script, count := BuildPowerShellScript("Write-Host done", vars, "")

	if count != 2 {
		t.Fatalf("expected 2 valid vars applied, got %d", count)
	}
	if !strings.Contains(script, "$GOOD = '1'\n") || !strings.Contains(script, "$PW = '4'\n") {
		t.Fatalf("expected valid vars in script:\n%s", script)
	}
	if strings.Contains(script, "BAD NAME") || strings.Contains(script, "9LEAD") {
		t.Fatalf("invalid var name leaked into script:\n%s", script)
	}
}

func TestBuildPowerShellScript_SystemInjectedSitsBetweenVarsAndUserCmd(t *testing.T) {
	vars := []UpdateVariable{
		{Name: "PW", Value: "secret"},
	}
	systemInjected := "$thumbprint = 'ABC123'\n$certificate = Get-Item ...\n"
	script, count := BuildPowerShellScript("Write-Host $PW $thumbprint", vars, systemInjected)

	if count != 1 {
		t.Fatalf("expected 1 var applied, got %d", count)
	}

	idxPreamble := strings.Index(script, "$ErrorActionPreference = 'Stop'")
	idxVar := strings.Index(script, "$PW = 'secret'")
	idxThumb := strings.Index(script, "$thumbprint = 'ABC123'")
	idxUserCmd := strings.Index(script, "Write-Host $PW $thumbprint")

	if idxPreamble < 0 || idxVar < 0 || idxThumb < 0 || idxUserCmd < 0 {
		t.Fatalf("missing expected lines:\n%s", script)
	}

	// Order must be: preamble → vars → system-injected → user cmd.
	if !(idxPreamble < idxVar && idxVar < idxThumb && idxThumb < idxUserCmd) {
		t.Fatalf("script ordering wrong (preamble=%d vars=%d thumb=%d user=%d):\n%s",
			idxPreamble, idxVar, idxThumb, idxUserCmd, script)
	}
}

func TestBuildPowerShellScript_SystemInjectedTrailingNewlineNotDuplicated(t *testing.T) {
	systemInjected := "$thumbprint = 'X'\n"
	script, _ := BuildPowerShellScript("Write-Host hi", nil, systemInjected)

	// Should contain the systemInjected once, with no doubled blank line.
	if strings.Contains(script, "\n\n") {
		t.Fatalf("unexpected blank line in script:\n%s", script)
	}
}
