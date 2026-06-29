//go:build windows

package agent

import (
	"strings"
	"testing"
)

func TestParseExchangeServices(t *testing.T) {
	// Detailed token canonicalization is covered by utils.CanonicalizeExchangeServices;
	// here we verify only the deploy-side wrapper: passthrough of a usable list and
	// the IIS,SMTP fallback when nothing usable remains.
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "empty falls back to default", value: "", want: "IIS,SMTP"},
		{name: "all unknown falls back to default", value: "nope,bad", want: "IIS,SMTP"},
		{name: "passes through usable services", value: "IIS, SMTP, IMAP", want: "IIS,SMTP,IMAP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseExchangeServices(tt.value); got != tt.want {
				t.Fatalf("parseExchangeServices(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestBuildExchangeScript(t *testing.T) {
	script := buildExchangeScript("ABC123", "IIS,SMTP")

	for _, want := range []string{
		"Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn",
		"$thumb = 'ABC123'",
		"Enable-ExchangeCertificate -Thumbprint $thumb -Services IIS,SMTP -Force",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}

func TestBuildExchangeScriptEscapesThumbprint(t *testing.T) {
	script := buildExchangeScript("AB'C", "IIS,SMTP")
	if !strings.Contains(script, "$thumb = 'AB''C'") {
		t.Fatalf("script missing escaped thumbprint assignment:\n%s", script)
	}
}
