package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestPollResponseDecodeKeepsVariablesOffDiskStruct enforces the contract
// that update_variables decodes into the in-memory VariablesByConfigId map
// and never reaches the disk-shaped CertificateConfiguration. If a future
// change accidentally adds UpdateVariables to config.CertificateConfiguration,
// this test fails because the substring would appear in the re-marshaled JSON.
func TestPollResponseDecodeKeepsVariablesOffDiskStruct(t *testing.T) {
	body := []byte(`{
		"updated_certificate_configurations": [
			{
				"config_id": "cfg-1",
				"certificate_id": "cert-1",
				"update_cmd": "echo hi",
				"update_variables": [
					{"name": "DB_PASSWORD", "value": "hunter2"},
					{"name": "API_TOKEN",   "value": "tok"}
				]
			}
		],
		"lock_requested": false
	}`)

	var wire pollResponseWire
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatalf("unmarshal wire: %v", err)
	}

	if len(wire.UpdatedCertificateConfigurations) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(wire.UpdatedCertificateConfigurations))
	}

	entry := wire.UpdatedCertificateConfigurations[0]
	if len(entry.UpdateVariables) != 2 {
		t.Fatalf("expected 2 vars on wire entry, got %d", len(entry.UpdateVariables))
	}

	// Re-marshal the disk-shaped CertificateConfiguration and confirm it
	// contains no trace of the variable name/value or the field key.
	diskBytes, err := json.Marshal(entry.CertificateConfiguration)
	if err != nil {
		t.Fatalf("marshal disk struct: %v", err)
	}
	disk := string(diskBytes)
	for _, leak := range []string{"update_variables", "DB_PASSWORD", "hunter2", "API_TOKEN", "tok"} {
		if strings.Contains(disk, leak) {
			t.Fatalf("disk-shaped CertificateConfiguration leaked %q: %s", leak, disk)
		}
	}
}

