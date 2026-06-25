//go:build windows

package inventory

import (
	"testing"

	"github.com/certkit-io/certkit-agent/api"
)

// sampleIISBindingsJSON mirrors the real {"value":[...],"Count":N} payload the
// inventory PowerShell emits (captured from a live applicationHost.config with a
// multi-SNI site and assorted sslFlags). HTTP bindings are already filtered out
// by the PowerShell, so they never appear here.
const sampleIISBindingsJSON = `{
    "value": [
        { "Site": "TrackJSWeb", "Port": "443", "Host": "local2.trackjs.com", "SslFlags": 1 },
        { "Site": "TrackJSWeb", "Port": "443", "Host": "local.trackjs.com", "SslFlags": 0 },
        { "Site": "Certloop", "Port": "443", "Host": "awesome2.certloop.dev", "SslFlags": 65 },
        { "Site": "SNI", "Port": "443", "Host": "sni1.trackjs.com", "SslFlags": 1 },
        { "Site": "SNI", "Port": "443", "Host": "sni2.trackjs.com", "SslFlags": 1 }
    ],
    "Count": 5
}`

func TestParseIISBindingsJSON(t *testing.T) {
	bindings := parseIISBindingsJSON(sampleIISBindingsJSON)
	if len(bindings) != 5 {
		t.Fatalf("expected 5 bindings, got %d", len(bindings))
	}

	// Spot-check the SNI binding with combined flags (65 = 64|1) survives intact.
	got := bindings[2]
	if got.Site != "Certloop" || got.Port != "443" || got.Host != "awesome2.certloop.dev" || got.SslFlags != 65 {
		t.Fatalf("unexpected binding[2]: %+v", got)
	}

	// The two SNI bindings share site+port and differ only by host header.
	if bindings[3].Host == bindings[4].Host {
		t.Fatalf("expected distinct SNI hosts, got %q twice", bindings[3].Host)
	}
}

func TestParseIISBindingsJSONEmpty(t *testing.T) {
	for _, raw := range []string{"", "null", `{"value":[],"Count":0}`} {
		if got := parseIISBindingsJSON(raw); len(got) != 0 {
			t.Fatalf("parseIISBindingsJSON(%q) = %v, want empty", raw, got)
		}
	}
}

func TestIISInventoryItems(t *testing.T) {
	bindings := []iisBinding{
		{Site: "SNI", Port: "443", Host: "sni1.trackjs.com", SslFlags: 1},
		{Site: "TrackJSWeb", Port: "443", Host: "local.trackjs.com", SslFlags: 0},
		{Site: "Default Web Site", Port: "443", Host: "", SslFlags: 0},
		{Site: "Certloop", Port: "443", Host: "awesome2.certloop.dev", SslFlags: 65},
	}

	items := iisInventoryItems(bindings)
	if len(items) != 4 {
		t.Fatalf("expected 4 items, got %d", len(items))
	}

	// Host is appended (site:port:host) only for SNI bindings (sslFlags bit 0x1).
	// Non-SNI bindings stay site:port even when they carry a host header
	// (TrackJSWeb). The host is always reported via Domains regardless.
	want := []api.InventoryItem{
		{
			Server:          "iis",
			ConfigPath:      `IIS:\Sites|SslFlags=1`,
			CertificatePath: "SNI:443:sni1.trackjs.com",
			KeyPath:         "SNI:443:sni1.trackjs.com",
			Domains:         "sni1.trackjs.com",
		},
		{
			Server:          "iis",
			ConfigPath:      `IIS:\Sites|SslFlags=0`,
			CertificatePath: "TrackJSWeb:443",
			KeyPath:         "TrackJSWeb:443",
			Domains:         "local.trackjs.com",
		},
		{
			Server:          "iis",
			ConfigPath:      `IIS:\Sites|SslFlags=0`,
			CertificatePath: "Default Web Site:443",
			KeyPath:         "Default Web Site:443",
			Domains:         "",
		},
		{
			Server:          "iis",
			ConfigPath:      `IIS:\Sites|SslFlags=65`,
			CertificatePath: "Certloop:443:awesome2.certloop.dev",
			KeyPath:         "Certloop:443:awesome2.certloop.dev",
			Domains:         "awesome2.certloop.dev",
		},
	}

	for i, w := range want {
		if items[i] != w {
			t.Fatalf("item[%d]\n got = %+v\nwant = %+v", i, items[i], w)
		}
	}
}
