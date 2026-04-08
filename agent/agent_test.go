package agent

import (
	"testing"
	"time"

	"github.com/certkit-io/certkit-agent/config"
)

func timePtr(t time.Time) *time.Time { return &t }

func TestDetectChangedConfigs(t *testing.T) {
	baseTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime := baseTime.Add(time.Hour)

	tests := []struct {
		name              string
		old               []config.CertificateConfiguration
		incoming          []config.CertificateConfiguration
		wantChanged       bool
		wantFormatChanged bool
		wantStaleFiles    []string
	}{
		{
			name: "no change when dates and sha1 match",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: true, PemDestination: "/a.pem"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: true, PemDestination: "/a.pem"},
			},
			wantChanged: false,
		},
		{
			name: "new config has no previous entry",
			old:  []config.CertificateConfiguration{},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), PemDestination: "/a.pem"},
			},
			wantChanged:       true,
			wantFormatChanged: false,
		},
		{
			name: "config changed but format unchanged",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: true, PemDestination: "/a.pem"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), LatestCertificateSha1: "def", AllInOne: true, PemDestination: "/a.pem"},
			},
			wantChanged:       true,
			wantFormatChanged: false,
		},
		{
			name: "AllInOne switched to PEM+Key, key reused",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: true, PemDestination: "/a.pem", KeyDestination: "/a.pem"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    nil, // key reused at same path, not all-in-one anymore so no stale key
		},
		{
			name: "PEM+Key switched to AllInOne, stale key file",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: true, PemDestination: "/a.pem", KeyDestination: "/a.pem"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    []string{"/a.key"},
		},
		{
			name: "PEM+Chain+Key switched to PEM+Key, stale chain file",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/a.chain"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: ""},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    []string{"/a.chain"},
		},
		{
			name: "PEM destination path changed, old pem is stale",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: true, PemDestination: "/old.pem"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: true, PemDestination: "/new.pem"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    []string{"/old.pem"},
		},
		{
			name: "PEM+Chain+Key switched to AllInOne, stale key and chain",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/a.chain"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: true, PemDestination: "/a.pem", KeyDestination: "/a.pem", ChainDestination: ""},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    []string{"/a.key", "/a.chain"},
		},
		{
			name: "sha1 changed triggers change",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", PemDestination: "/a.pem"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "def", PemDestination: "/a.pem"},
			},
			wantChanged:       true,
			wantFormatChanged: false,
		},
		{
			name: "PEM+Key switched to PEM+Chain+Key, no stale files",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/a.chain"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    nil,
		},
		{
			name: "key destination path changed, old key is stale",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/old.key"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/new.key"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    []string{"/old.key"},
		},
		{
			name: "chain destination path changed, old chain is stale",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/old.chain"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/new.chain"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    []string{"/old.chain"},
		},
		{
			name: "Windows cert store skips stale file logic",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), ConfigType: "iis", PemDestination: "OldSite:443", KeyDestination: "/old.key"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), ConfigType: "iis", PemDestination: "NewSite:443", KeyDestination: "/new.key"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    nil,
		},
		{
			name: "JKS only tracks PEM destination, not key or chain",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), ConfigType: "jks", PemDestination: "/a.jks", KeyDestination: "/old.pass", ChainDestination: "/old.chain"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), ConfigType: "jks", PemDestination: "/a.jks", KeyDestination: "/new.pass", ChainDestination: "/new.chain"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    nil, // key/chain changes ignored for JKS, pem path unchanged
		},
		{
			name: "JKS with PEM destination changed produces stale pem",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), ConfigType: "jks", PemDestination: "/old.jks"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), ConfigType: "jks", PemDestination: "/new.jks"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    []string{"/old.jks"},
		},
		{
			name: "format changed but dates and sha1 unchanged",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: true, PemDestination: "/a.pem", KeyDestination: "/a.pem"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key"},
			},
			wantChanged:       false,
			wantFormatChanged: true,
			wantStaleFiles:    nil, // old key dest "/a.pem" is still active as pem dest
		},
		{
			name: "IsPfx toggled triggers format change",
			old: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), IsPfx: false, PemDestination: "/a.pem"},
			},
			incoming: []config.CertificateConfiguration{
				{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), IsPfx: true, PemDestination: "/a.pem"},
			},
			wantChanged:       true,
			wantFormatChanged: true,
			wantStaleFiles:    nil,
		},
		{
			name: "empty incoming list returns empty map",
			old: []config.CertificateConfiguration{
				{Id: "a", PemDestination: "/a.pem"},
			},
			incoming:       []config.CertificateConfiguration{},
			wantChanged:    false,
			wantStaleFiles: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectChangedConfigs(tt.old, tt.incoming)
			id := ""
			if len(tt.incoming) > 0 {
				id = tt.incoming[0].Id
			}

			change, exists := result[id]
			if len(tt.incoming) == 0 {
				if len(result) != 0 {
					t.Fatalf("expected empty map for empty incoming, got %d entries", len(result))
				}
				return
			}
			if !exists {
				t.Fatalf("expected entry for config %q in result map, got none", id)
			}

			if change.Changed != tt.wantChanged {
				t.Fatalf("Changed = %v, want %v", change.Changed, tt.wantChanged)
			}

			if change.FormatChanged != tt.wantFormatChanged {
				t.Fatalf("FormatChanged = %v, want %v", change.FormatChanged, tt.wantFormatChanged)
			}

			if len(change.StaleFiles) != len(tt.wantStaleFiles) {
				t.Fatalf("StaleFiles = %v, want %v", change.StaleFiles, tt.wantStaleFiles)
			}
			for i, f := range change.StaleFiles {
				if f != tt.wantStaleFiles[i] {
					t.Fatalf("StaleFiles[%d] = %q, want %q", i, f, tt.wantStaleFiles[i])
				}
			}
		})
	}
}
