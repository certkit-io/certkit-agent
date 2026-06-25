//go:build windows

package agent

import (
	"strings"
	"testing"
)

func TestParseIISDestination(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		wantSite string
		wantPort string
		wantHost string
		wantErr  bool
	}{
		{name: "site and port", value: "Default Web Site:443", wantSite: "Default Web Site", wantPort: "443"},
		{name: "site port and host", value: "Certkit Web Site:44300:test.certkit.io", wantSite: "Certkit Web Site", wantPort: "44300", wantHost: "test.certkit.io"},
		{name: "trims surrounding whitespace", value: " site : 443 : host ", wantSite: "site", wantPort: "443", wantHost: "host"},
		{name: "empty", value: "", wantErr: true},
		{name: "missing port", value: "siteonly", wantErr: true},
		{name: "blank port", value: "site:", wantErr: true},
		{name: "blank site", value: ":443", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			site, port, host, err := parseIISDestination(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got none", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.value, err)
			}
			if site != tt.wantSite || port != tt.wantPort || host != tt.wantHost {
				t.Fatalf("parseIISDestination(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.value, site, port, host, tt.wantSite, tt.wantPort, tt.wantHost)
			}
		})
	}
}

func TestIISThreePartDestinationDrivesSNI(t *testing.T) {
	// A three-part destination (site:port:host) is the sole SNI signal: it yields a
	// host, which makes the binding lookup host-scoped. A two-part destination does
	// not, and falls back to the historical host-agnostic lookup.
	site, port, host, err := parseIISDestination("Web:443:app.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host == "" {
		t.Fatal("expected non-empty host from three-part destination")
	}
	if !strings.Contains(buildIISBindingScript(site, port, host, "T"), "-HostHeader $bindingHost") {
		t.Fatal("three-part destination should produce an SNI (host-scoped) lookup")
	}

	site, port, host, err = parseIISDestination("Web:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "" {
		t.Fatalf("expected empty host from two-part destination, got %q", host)
	}
	if strings.Contains(buildIISBindingScript(site, port, host, "T"), "-HostHeader") {
		t.Fatal("two-part destination should produce a non-SNI (host-agnostic) lookup")
	}
}

func TestBuildIISBindingScriptNonSNI(t *testing.T) {
	script := buildIISBindingScript("Default Web Site", "443", "", "ABC123")

	if !strings.Contains(script, "Get-WebBinding -Name $site -Protocol https -Port $port\n") {
		t.Fatalf("non-SNI script missing host-agnostic lookup:\n%s", script)
	}
	if strings.Contains(script, "-HostHeader") {
		t.Fatalf("non-SNI script should not scope by host header:\n%s", script)
	}
}

func TestBuildIISBindingScriptSNI(t *testing.T) {
	script := buildIISBindingScript("Certkit Web Site", "44300", "test.certkit.io", "ABC123")

	if !strings.Contains(script, "Get-WebBinding -Name $site -Protocol https -Port $port -HostHeader $bindingHost") {
		t.Fatalf("SNI script missing host-scoped lookup:\n%s", script)
	}
	if !strings.Contains(script, "$bindingHost = 'test.certkit.io'") {
		t.Fatalf("SNI script missing host assignment:\n%s", script)
	}
}

func TestBuildIISBindingScriptEscapesSingleQuotes(t *testing.T) {
	script := buildIISBindingScript("Sit'e", "443", "ho'st", "AB'C")

	for _, want := range []string{"$site        = 'Sit''e'", "$bindingHost = 'ho''st'", "$newThumb    = 'AB''C'"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing escaped assignment %q:\n%s", want, script)
		}
	}
}
