package agent

import (
	"slices"
	"testing"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

func timePtr(t time.Time) *time.Time { return &t }

var (
	baseTime = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	newTime  = baseTime.Add(time.Hour)
)

func assertConfigChange(t *testing.T, result map[string]ConfigChange, id string, wantChanged, wantFormatChanged bool, wantStaleFiles []string) {
	t.Helper()
	change, exists := result[id]
	if !exists {
		t.Fatalf("expected entry for config %q in result map, got none", id)
	}
	if change.Changed != wantChanged {
		t.Fatalf("Changed = %v, want %v", change.Changed, wantChanged)
	}
	if change.FormatChanged != wantFormatChanged {
		t.Fatalf("FormatChanged = %v, want %v", change.FormatChanged, wantFormatChanged)
	}
	if !slices.Equal(change.StaleFiles, wantStaleFiles) {
		t.Fatalf("StaleFiles = %v, want %v", change.StaleFiles, wantStaleFiles)
	}
}

func TestDetectChangedConfigs_NoChangeWhenDatesAndSha1Match(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: true, PemDestination: "/a.pem"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: true, PemDestination: "/a.pem"},
		},
	)
	assertConfigChange(t, result, "a", false, false, nil)
}

func TestDetectChangedConfigs_NewConfigHasNoPreviousEntry(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), PemDestination: "/a.pem"},
		},
	)
	assertConfigChange(t, result, "a", true, false, nil)
}

func TestDetectChangedConfigs_ConfigChangedButFormatUnchanged(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: true, PemDestination: "/a.pem"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), LatestCertificateSha1: "def", AllInOne: true, PemDestination: "/a.pem"},
		},
	)
	assertConfigChange(t, result, "a", true, false, nil)
}

func TestDetectChangedConfigs_AllInOneSwitchedToPEMKey(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: true, PemDestination: "/a.pem", KeyDestination: "/a.pem"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key"},
		},
	)
	// Old key dest "/a.pem" is still active as PEM destination, not stale.
	assertConfigChange(t, result, "a", true, true, nil)
}

func TestDetectChangedConfigs_PEMKeySwitchedToAllInOne(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: true, PemDestination: "/a.pem", KeyDestination: "/a.pem"},
		},
	)
	assertConfigChange(t, result, "a", true, true, []string{"/a.key"})
}

func TestDetectChangedConfigs_PEMChainKeySwitchedToPEMKey(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/a.chain"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: ""},
		},
	)
	assertConfigChange(t, result, "a", true, true, []string{"/a.chain"})
}

func TestDetectChangedConfigs_PEMDestinationPathChanged(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: true, PemDestination: "/old.pem"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: true, PemDestination: "/new.pem"},
		},
	)
	assertConfigChange(t, result, "a", true, true, []string{"/old.pem"})
}

func TestDetectChangedConfigs_PEMChainKeySwitchedToAllInOne(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/a.chain"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: true, PemDestination: "/a.pem", KeyDestination: "/a.pem", ChainDestination: ""},
		},
	)
	assertConfigChange(t, result, "a", true, true, []string{"/a.key", "/a.chain"})
}

func TestDetectChangedConfigs_Sha1ChangedTriggersChange(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", PemDestination: "/a.pem"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "def", PemDestination: "/a.pem"},
		},
	)
	assertConfigChange(t, result, "a", true, false, nil)
}

func TestDetectChangedConfigs_PEMKeySwitchedToPEMChainKey(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/a.chain"},
		},
	)
	assertConfigChange(t, result, "a", true, true, nil)
}

func TestDetectChangedConfigs_KeyDestinationPathChanged(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/old.key"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/new.key"},
		},
	)
	assertConfigChange(t, result, "a", true, true, []string{"/old.key"})
}

func TestDetectChangedConfigs_ChainDestinationPathChanged(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/old.chain"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key", ChainDestination: "/new.chain"},
		},
	)
	assertConfigChange(t, result, "a", true, true, []string{"/old.chain"})
}

func TestDetectChangedConfigs_WindowsCertStoreSkipsStaleFileLogic(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), ConfigType: "iis", PemDestination: "OldSite:443", KeyDestination: "/old.key"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), ConfigType: "iis", PemDestination: "NewSite:443", KeyDestination: "/new.key"},
		},
	)
	assertConfigChange(t, result, "a", true, true, nil)
}

func TestDetectChangedConfigs_JKSOnlyTracksPEMDestination(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), ConfigType: "jks", PemDestination: "/a.jks", KeyDestination: "/old.pass", ChainDestination: "/old.chain"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), ConfigType: "jks", PemDestination: "/a.jks", KeyDestination: "/new.pass", ChainDestination: "/new.chain"},
		},
	)
	// Key/chain changes ignored for JKS, PEM path unchanged.
	assertConfigChange(t, result, "a", true, true, nil)
}

func TestDetectChangedConfigs_JKSWithPEMDestinationChanged(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), ConfigType: "jks", PemDestination: "/old.jks"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), ConfigType: "jks", PemDestination: "/new.jks"},
		},
	)
	assertConfigChange(t, result, "a", true, true, []string{"/old.jks"})
}

func TestDetectChangedConfigs_FormatChangedButDatesAndSha1Unchanged(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: true, PemDestination: "/a.pem", KeyDestination: "/a.pem"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), LatestCertificateSha1: "abc", AllInOne: false, PemDestination: "/a.pem", KeyDestination: "/a.key"},
		},
	)
	// Old key dest "/a.pem" is still active as PEM destination.
	assertConfigChange(t, result, "a", false, true, nil)
}

func TestDetectChangedConfigs_IsPfxToggledTriggersFormatChange(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(baseTime), IsPfx: false, PemDestination: "/a.pem"},
		},
		[]config.CertificateConfiguration{
			{Id: "a", LastConfigurationUpdateDate: timePtr(newTime), IsPfx: true, PemDestination: "/a.pem"},
		},
	)
	assertConfigChange(t, result, "a", true, true, nil)
}

func TestDetectChangedConfigs_EmptyIncomingListReturnsEmptyMap(t *testing.T) {
	result := detectChangedConfigs(
		[]config.CertificateConfiguration{
			{Id: "a", PemDestination: "/a.pem"},
		},
		[]config.CertificateConfiguration{},
	)
	if len(result) != 0 {
		t.Fatalf("expected empty map for empty incoming, got %d entries", len(result))
	}
}

func TestUpdateVariableStoreRoundTripAndReplace(t *testing.T) {
	t.Cleanup(func() { setUpdateVariables(nil) })

	setUpdateVariables(map[string][]api.UpdateVariable{
		"cfg-a": {{Name: "DB_PASSWORD", Value: "hunter2"}},
		"cfg-b": {{Name: "API_TOKEN", Value: "tok"}},
	})

	if got := getUpdateVariables("cfg-a"); len(got) != 1 || got[0].Value != "hunter2" {
		t.Fatalf("cfg-a roundtrip failed: %+v", got)
	}
	if got := getUpdateVariables("missing"); got != nil {
		t.Fatalf("missing key should return nil, got %+v", got)
	}

	// Replace wholesale — cfg-a must disappear because the new map omits it.
	setUpdateVariables(map[string][]api.UpdateVariable{
		"cfg-b": {{Name: "API_TOKEN", Value: "rotated"}},
	})
	if got := getUpdateVariables("cfg-a"); got != nil {
		t.Fatalf("cfg-a should be gone after replace, got %+v", got)
	}
	if got := getUpdateVariables("cfg-b"); len(got) != 1 || got[0].Value != "rotated" {
		t.Fatalf("cfg-b should reflect rotated value, got %+v", got)
	}

	// nil clears — required so a poll response with no vars wipes the store.
	setUpdateVariables(nil)
	if got := getUpdateVariables("cfg-b"); got != nil {
		t.Fatalf("nil setter should clear, got %+v", got)
	}
}

func TestIsValidVariableName(t *testing.T) {
	good := []string{"DB", "_X", "DB_PASSWORD", "x9", "_0", "Mixed_Case_99"}
	bad := []string{"", "9LEAD", "FOO BAR", "FOO;rm", "FOO-BAR", "FOO$", "FOO\nBAR"}

	for _, name := range good {
		if !isValidVariableName(name) {
			t.Errorf("expected %q to be valid", name)
		}
	}
	for _, name := range bad {
		if isValidVariableName(name) {
			t.Errorf("expected %q to be invalid", name)
		}
	}
}
