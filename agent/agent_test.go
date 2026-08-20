package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
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

func TestPreserveUnresolvedStatuses_PreservesUpdateCommandFailure(t *testing.T) {
	incoming := []config.CertificateConfiguration{
		{Id: "a", LastStatus: statusSynced},
	}

	preserveUnresolvedStatuses(
		[]config.CertificateConfiguration{
			{Id: "a", LastStatus: statusErrorUpdateCmd},
		},
		incoming,
	)

	if incoming[0].LastStatus != statusErrorUpdateCmd {
		t.Fatalf("LastStatus = %q, want %q", incoming[0].LastStatus, statusErrorUpdateCmd)
	}
}

func TestPreserveUnresolvedStatuses_DoesNotPreserveSynced(t *testing.T) {
	incoming := []config.CertificateConfiguration{
		{Id: "a", LastStatus: ""},
	}

	preserveUnresolvedStatuses(
		[]config.CertificateConfiguration{
			{Id: "a", LastStatus: statusSynced},
		},
		incoming,
	)

	if incoming[0].LastStatus != "" {
		t.Fatalf("LastStatus = %q, want empty", incoming[0].LastStatus)
	}
}

func TestApplyLockedConfigUpdates_RenewalClearsSyncedStatus(t *testing.T) {
	previousConfig := config.CurrentConfig
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
	})

	config.CurrentConfig = config.Config{
		CertificateConfigurations: []config.CertificateConfiguration{
			{Id: "a", LatestCertificateSha1: "abc", LastStatus: statusSynced},
		},
	}

	result := applyLockedConfigUpdates([]config.CertificateConfiguration{
		{Id: "a", LatestCertificateSha1: "def"},
	})

	assertConfigChange(t, result, "a", true, false, nil)
	if got := config.CurrentConfig.CertificateConfigurations[0].LastStatus; got != "" {
		t.Fatalf("LastStatus = %q, want empty (SYNCED must reset so the post-renewal report isn't suppressed)", got)
	}
	if got := config.CurrentConfig.CertificateConfigurations[0].LatestCertificateSha1; got != "def" {
		t.Fatalf("LatestCertificateSha1 = %q, want %q", got, "def")
	}
}

func TestApplyLockedConfigUpdates_RenewalPreservesUnresolvedStatus(t *testing.T) {
	previousConfig := config.CurrentConfig
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
	})

	for _, status := range []string{statusErrorUpdateCmd, statusWaitingWindow} {
		config.CurrentConfig = config.Config{
			CertificateConfigurations: []config.CertificateConfiguration{
				{Id: "a", LatestCertificateSha1: "abc", LastStatus: status},
			},
		}

		result := applyLockedConfigUpdates([]config.CertificateConfiguration{
			{Id: "a", LatestCertificateSha1: "def"},
		})

		assertConfigChange(t, result, "a", true, false, nil)
		if got := config.CurrentConfig.CertificateConfigurations[0].LastStatus; got != status {
			t.Fatalf("LastStatus = %q, want %q preserved", got, status)
		}
	}
}

func TestApplyLockedConfigUpdates_NoSha1ChangeLeavesStatusAlone(t *testing.T) {
	previousConfig := config.CurrentConfig
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
	})

	config.CurrentConfig = config.Config{
		CertificateConfigurations: []config.CertificateConfiguration{
			{Id: "a", LatestCertificateSha1: "abc", LastStatus: statusSynced},
		},
	}

	result := applyLockedConfigUpdates([]config.CertificateConfiguration{
		{Id: "a", LatestCertificateSha1: "abc"},
	})

	if len(result) != 0 {
		t.Fatalf("len(result) = %d, want 0", len(result))
	}
	if got := config.CurrentConfig.CertificateConfigurations[0].LastStatus; got != statusSynced {
		t.Fatalf("LastStatus = %q, want %q", got, statusSynced)
	}
}

func TestIsUnresolvedStatus(t *testing.T) {
	unresolved := []string{
		statusErrorUpdateCmd,
		statusWaitingWindow,
		statusErrorGetCert,
		statusErrorWriteCert,
		statusErrorGeneral,
	}

	for _, status := range unresolved {
		if !isUnresolvedStatus(status) {
			t.Fatalf("isUnresolvedStatus(%q) = false, want true", status)
		}
	}

	for _, status := range []string{"", statusSynced} {
		if isUnresolvedStatus(status) {
			t.Fatalf("isUnresolvedStatus(%q) = true, want false", status)
		}
	}
}

func TestIsPendingWorkStatus(t *testing.T) {
	if !isPendingWorkStatus(statusWaitingWindow) {
		t.Fatalf("isPendingWorkStatus(%q) = false, want true", statusWaitingWindow)
	}

	// Error statuses must NOT re-enter synchronization on an unchanged
	// config — a failure sticks until the config is saved again on the app.
	for _, status := range []string{"", statusSynced, statusErrorUpdateCmd, statusErrorGetCert, statusErrorWriteCert, statusErrorGeneral} {
		if isPendingWorkStatus(status) {
			t.Fatalf("isPendingWorkStatus(%q) = true, want false", status)
		}
	}
}

func TestSynchronizeCertificates_DoesNotRetryFailureDuringNormalPoll(t *testing.T) {
	previousConfig := config.CurrentConfig
	previousPath := config.CurrentPath
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
		config.CurrentPath = previousPath
	})

	config.CurrentPath = filepath.Join(t.TempDir(), "config.json")
	config.CurrentConfig = config.Config{
		CertificateConfigurations: []config.CertificateConfiguration{
			{
				Id:            "a",
				CertificateId: "cert-a",
				LastStatus:    statusErrorUpdateCmd,
			},
		},
	}

	statuses := SynchronizeCertificates(nil, false)

	if len(statuses) != 0 {
		t.Fatalf("len(statuses) = %d, want 0 (failed config must not retry without a change)", len(statuses))
	}
	if got := config.CurrentConfig.CertificateConfigurations[0].LastStatus; got != statusErrorUpdateCmd {
		t.Fatalf("LastStatus = %q, want %q preserved", got, statusErrorUpdateCmd)
	}
}

func TestSynchronizeCertificates_ReportsRepeatedErrorStatusOnRetry(t *testing.T) {
	previousConfig := config.CurrentConfig
	previousPath := config.CurrentPath
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
		config.CurrentPath = previousPath
	})

	config.CurrentPath = filepath.Join(t.TempDir(), "config.json")
	config.CurrentConfig = config.Config{
		CertificateConfigurations: []config.CertificateConfiguration{
			{
				// Missing destination paths fail with ERROR_GENERAL, the same
				// status the config is already in — the retry (triggered by a
				// config change) must still be reported so the backend sees
				// the fresh message.
				Id:            "a",
				CertificateId: "cert-a",
				LastStatus:    statusErrorGeneral,
			},
		},
	}

	statuses := SynchronizeCertificates(map[string]ConfigChange{"a": {Changed: true}}, false)

	if len(statuses) != 1 {
		t.Fatalf("len(statuses) = %d, want 1", len(statuses))
	}
	if statuses[0].Status != statusErrorGeneral {
		t.Fatalf("Status = %q, want %q", statuses[0].Status, statusErrorGeneral)
	}
}

// writeSelfSignedCertPEM writes a freshly generated self-signed certificate to
// path and returns its SHA1 fingerprint in hex.
func writeSelfSignedCertPEM(t *testing.T, path string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "certkit-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	sum := sha1.Sum(der)
	return hex.EncodeToString(sum[:])
}

func TestSynchronizeCertificates_ForceSyncPreservesFailureWhenNothingToDo(t *testing.T) {
	previousConfig := config.CurrentConfig
	previousPath := config.CurrentPath
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
		config.CurrentPath = previousPath
	})

	// The on-disk certificate matches the expected SHA1, so a force sync (as
	// happens on every agent restart) has nothing to do. The standing update
	// command failure must persist — no erroneous SYNCED may be pushed.
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	certSha1 := writeSelfSignedCertPEM(t, certPath)

	config.CurrentPath = filepath.Join(t.TempDir(), "config.json")
	config.CurrentConfig = config.Config{
		CertificateConfigurations: []config.CertificateConfiguration{
			{
				Id:                    "a",
				CertificateId:         "cert-a",
				PemDestination:        certPath,
				AllInOne:              true,
				LatestCertificateSha1: certSha1,
				UpdateCmd:             "echo hi",
				LastStatus:            statusErrorUpdateCmd,
			},
		},
	}

	statuses := SynchronizeCertificates(nil, true)

	if len(statuses) != 0 {
		t.Fatalf("len(statuses) = %d, want 0 (got %+v)", len(statuses), statuses)
	}
	if got := config.CurrentConfig.CertificateConfigurations[0].LastStatus; got != statusErrorUpdateCmd {
		t.Fatalf("LastStatus = %q, want %q preserved", got, statusErrorUpdateCmd)
	}
}

func TestSynchronizeCertificates_ForceSyncStaysQuietWhenSyncedAndUnchanged(t *testing.T) {
	previousConfig := config.CurrentConfig
	previousPath := config.CurrentPath
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
		config.CurrentPath = previousPath
	})

	// The on-disk certificate matches and the local status is already SYNCED.
	// A force sync runs the synchronization checks but reports nothing when
	// the outcome matches the last reported status.
	certPath := filepath.Join(t.TempDir(), "cert.pem")
	certSha1 := writeSelfSignedCertPEM(t, certPath)

	config.CurrentPath = filepath.Join(t.TempDir(), "config.json")
	config.CurrentConfig = config.Config{
		CertificateConfigurations: []config.CertificateConfiguration{
			{
				Id:                    "a",
				CertificateId:         "cert-a",
				PemDestination:        certPath,
				AllInOne:              true,
				LatestCertificateSha1: certSha1,
				LastStatus:            statusSynced,
			},
		},
	}

	statuses := SynchronizeCertificates(nil, true)

	if len(statuses) != 0 {
		t.Fatalf("len(statuses) = %d, want 0 (unchanged SYNCED config must not re-report on force sync, got %+v)", len(statuses), statuses)
	}
}

func TestSynchronizeCertificates_NormalPollStaysQuietWhenSyncedAndUnchanged(t *testing.T) {
	previousConfig := config.CurrentConfig
	previousPath := config.CurrentPath
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
		config.CurrentPath = previousPath
	})

	certPath := filepath.Join(t.TempDir(), "cert.pem")
	certSha1 := writeSelfSignedCertPEM(t, certPath)

	config.CurrentPath = filepath.Join(t.TempDir(), "config.json")
	config.CurrentConfig = config.Config{
		CertificateConfigurations: []config.CertificateConfiguration{
			{
				Id:                    "a",
				CertificateId:         "cert-a",
				PemDestination:        certPath,
				AllInOne:              true,
				LatestCertificateSha1: certSha1,
				LastStatus:            statusSynced,
			},
		},
	}

	statuses := SynchronizeCertificates(nil, false)

	if len(statuses) != 0 {
		t.Fatalf("len(statuses) = %d, want 0 (unchanged SYNCED config must not chatter on normal polls, got %+v)", len(statuses), statuses)
	}
}

func TestIsErrorStatus(t *testing.T) {
	for _, status := range []string{statusErrorUpdateCmd, statusErrorGetCert, statusErrorWriteCert, statusErrorGeneral} {
		if !isErrorStatus(status) {
			t.Fatalf("isErrorStatus(%q) = false, want true", status)
		}
	}

	for _, status := range []string{"", statusSynced, statusWaitingWindow} {
		if isErrorStatus(status) {
			t.Fatalf("isErrorStatus(%q) = true, want false", status)
		}
	}
}

func TestUpdateVariableStoreRoundTripAndReplace(t *testing.T) {
	t.Cleanup(func() { setUpdateVariables(nil) })

	setUpdateVariables(map[string][]utils.UpdateVariable{
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
	setUpdateVariables(map[string][]utils.UpdateVariable{
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
