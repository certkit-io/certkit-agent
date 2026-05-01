//go:build !windows

package agent

import (
	"strings"
	"testing"

	"github.com/certkit-io/certkit-agent/utils"
)

func TestBuildShellScript_NoVarsEmitsPreambleAndCommand(t *testing.T) {
	script, count := buildShellScript("set -euo pipefail\n", "echo hi", nil)

	if count != 0 {
		t.Fatalf("expected 0 vars applied, got %d", count)
	}
	want := "set -euo pipefail\necho hi\n"
	if script != want {
		t.Fatalf("script mismatch:\n got: %q\nwant: %q", script, want)
	}
}

func TestBuildShellScript_PreservesEmbeddedNewlinesInUpdateCmd(t *testing.T) {
	updateCmd := "set\nfor i in 1 2 3; do\n  echo $i\ndone"
	script, _ := buildShellScript("set -eu\n", updateCmd, nil)

	if !strings.Contains(script, updateCmd) {
		t.Fatalf("multiline update_cmd was modified during script build:\n%s", script)
	}
	if !strings.HasSuffix(script, "\n") {
		t.Fatalf("script must end with newline:\n%s", script)
	}
}

func TestBuildShellScript_EscapesSingleQuotesInValue(t *testing.T) {
	vars := []utils.UpdateVariable{
		{Name: "PW", Value: "it's a secret"},
	}
	script, count := buildShellScript("set -eu\n", "echo $PW", vars)

	if count != 1 {
		t.Fatalf("expected 1 var applied, got %d", count)
	}
	// Standard POSIX single-quote escape: close, escaped quote, reopen.
	wantLine := `export PW='it'\''s a secret'`
	if !strings.Contains(script, wantLine) {
		t.Fatalf("expected escaped single-quote line %q in script:\n%s", wantLine, script)
	}
}

func TestBuildShellScript_SkipsInvalidVariableNames(t *testing.T) {
	vars := []utils.UpdateVariable{
		{Name: "GOOD", Value: "1"},
		{Name: "BAD NAME", Value: "2"},
		{Name: "9LEAD", Value: "3"},
		{Name: "PW", Value: "4"},
	}
	script, count := buildShellScript("set -eu\n", "echo done", vars)

	if count != 2 {
		t.Fatalf("expected 2 valid vars applied, got %d", count)
	}
	if !strings.Contains(script, "export GOOD='1'\n") || !strings.Contains(script, "export PW='4'\n") {
		t.Fatalf("expected valid vars in script:\n%s", script)
	}
	if strings.Contains(script, "BAD NAME") || strings.Contains(script, "9LEAD") {
		t.Fatalf("invalid var name leaked into script:\n%s", script)
	}
}
