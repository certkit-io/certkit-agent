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

func TestServicesIncludeSMTP(t *testing.T) {
	tests := []struct {
		services string
		want     bool
	}{
		{services: "IIS,SMTP", want: true},
		{services: "SMTP", want: true},
		{services: "SMTPClientAuth", want: false},
		{services: "IIS", want: false},
		{services: "IIS,SMTPClientAuth,SMTP", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.services, func(t *testing.T) {
			if got := servicesIncludeSMTP(tt.services); got != tt.want {
				t.Fatalf("servicesIncludeSMTP(%q) = %t, want %t", tt.services, got, tt.want)
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

func TestBuildExchangeScriptIncludesConnectorBlock(t *testing.T) {
	script := buildExchangeScript("ABC123", "IIS,SMTP")

	// The regex literal doubles as proof the connector block bypassed
	// fmt.Sprintf unmangled.
	for _, want := range []string{
		"Get-ReceiveConnector -Server $env:COMPUTERNAME",
		"Get-SendConnector",
		"Set-ReceiveConnector -Identity $conn.Identity -TlsCertificateName $newTls",
		"Set-SendConnector -Identity $conn.Identity -TlsCertificateName $newTls",
		`'(?i)^<I>(.*)<S>(.*)$'`,
		`"<I>$($cert.Issuer)<S>$($cert.Subject)"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}

func TestBuildExchangeScriptOmitsConnectorBlockForNonSMTP(t *testing.T) {
	tests := []struct {
		name     string
		services string
	}{
		{name: "iis only", services: "IIS"},
		{name: "smtp client auth is not smtp", services: "IIS,SMTPClientAuth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := buildExchangeScript("ABC123", tt.services)
			for _, unwanted := range []string{"Set-SendConnector", "Set-ReceiveConnector", "TlsCertificateName"} {
				if strings.Contains(script, unwanted) {
					t.Fatalf("script for services %q should not contain %q:\n%s", tt.services, unwanted, script)
				}
			}
			if !strings.Contains(script, "Enable-ExchangeCertificate -Thumbprint $thumb -Services "+tt.services+" -Force") {
				t.Fatalf("script missing enable line for services %q:\n%s", tt.services, script)
			}
		})
	}
}

func TestBuildExchangeScriptEscapesThumbprint(t *testing.T) {
	script := buildExchangeScript("AB'C", "IIS,SMTP")
	if !strings.Contains(script, "$thumb = 'AB''C'") {
		t.Fatalf("script missing escaped thumbprint assignment:\n%s", script)
	}
}
