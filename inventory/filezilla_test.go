package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseFileZillaConfigSettingsXML(t *testing.T) {
	cert, key, domains, err := parseFileZillaConfig(filepath.Join("testdata", "filezilla-settings.xml"))
	if err != nil {
		t.Fatalf("parseFileZillaConfig returned error: %v", err)
	}

	assertString(t, cert, "/etc/ssl/certs/filezilla.pem")
	assertString(t, key, "/etc/ssl/private/filezilla.key")
	assertStringSlice(t, domains, []string{"ftp.example.test"})
}

func TestParseFileZillaConfigRejectsUnexpectedCertificateValue(t *testing.T) {
	path := writeTempFile(t, "settings.xml", `<?xml version="1.0" encoding="UTF-8"?>
<filezilla>
  <ftp_server>
    <session>
      <tls>
        <key type="filepath">/etc/ssl/private/filezilla.key</key>
        <certs type="pkcs11">token:cert</certs>
      </tls>
    </session>
  </ftp_server>
</filezilla>`)

	_, _, _, err := parseFileZillaConfig(path)
	if err == nil {
		t.Fatal("expected parseFileZillaConfig to reject a non-file certificate value")
	}
}

func writeTempFile(t *testing.T, name string, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func assertStringSlice(t *testing.T, actual []string, expected []string) {
	t.Helper()

	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("expected %v, got %v", expected, actual)
	}
}

func assertString(t *testing.T, actual string, expected string) {
	t.Helper()

	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}
