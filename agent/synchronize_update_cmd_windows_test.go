//go:build windows

package agent

import (
	"strings"
	"testing"

	"github.com/certkit-io/certkit-agent/api"
)

func TestBuildPowerShellScript_NoVarsEmitsPreambleAndCommand(t *testing.T) {
	script, count := buildPowerShellScript("Write-Host hi", nil, "cfg-a")

	if count != 0 {
		t.Fatalf("expected 0 vars applied, got %d", count)
	}
	want := "$ErrorActionPreference = 'Stop'\nWrite-Host hi\n"
	if script != want {
		t.Fatalf("script mismatch:\n got: %q\nwant: %q", script, want)
	}
}

func TestBuildPowerShellScript_PreservesEmbeddedNewlinesInUpdateCmd(t *testing.T) {
	updateCmd := "Write-Host one\nforeach ($i in 1..3) {\n  Write-Host $i\n}"
	script, _ := buildPowerShellScript(updateCmd, nil, "cfg-a")

	if !strings.Contains(script, updateCmd) {
		t.Fatalf("multiline update_cmd was modified during script build:\n%s", script)
	}
	if !strings.HasSuffix(script, "\n") {
		t.Fatalf("script must end with newline:\n%s", script)
	}
}

func TestBuildPowerShellScript_EscapesSingleQuotesInValue(t *testing.T) {
	vars := []api.UpdateVariable{
		{Name: "PW", Value: "it's a secret"},
	}
	script, count := buildPowerShellScript("Write-Host $PW", vars, "cfg-a")

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
	vars := []api.UpdateVariable{
		{Name: "GOOD", Value: "1"},
		{Name: "BAD NAME", Value: "2"},
		{Name: "9LEAD", Value: "3"},
		{Name: "PW", Value: "4"},
	}
	script, count := buildPowerShellScript("Write-Host done", vars, "cfg-a")

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

func TestBuildWindowsCertStoreScript_OrderingAndCertLoad(t *testing.T) {
	vars := []api.UpdateVariable{
		{Name: "PW", Value: "secret"},
	}
	script, count := buildWindowsCertStoreScript("ABC123", "Write-Host $PW $thumbprint", vars)

	if count != 1 {
		t.Fatalf("expected 1 var applied, got %d", count)
	}

	idxPreamble := strings.Index(script, "$ErrorActionPreference = 'Stop'")
	idxVar := strings.Index(script, "$PW = 'secret'")
	idxCert := strings.Index(script, "$certificate = Get-Item")
	idxUserCmd := strings.Index(script, "Write-Host $PW $thumbprint")

	if idxPreamble < 0 || idxVar < 0 || idxCert < 0 || idxUserCmd < 0 {
		t.Fatalf("missing expected lines:\n%s", script)
	}

	// Order must be: preamble → vars → cert load → user cmd
	if !(idxPreamble < idxVar && idxVar < idxCert && idxCert < idxUserCmd) {
		t.Fatalf("script ordering wrong (preamble=%d vars=%d cert=%d user=%d):\n%s",
			idxPreamble, idxVar, idxCert, idxUserCmd, script)
	}
}
