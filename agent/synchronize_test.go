package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseFileMode(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    uint32
		wantErr bool
	}{
		{
			name:  "octal with 0o prefix",
			value: "0o644",
			want:  0o644,
		},
		{
			name:  "octal with 0o prefix 600",
			value: "0o600",
			want:  0o600,
		},
		{
			name:    "invalid",
			value:   "nope",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFileMode(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseFileMode(%q) expected error", tt.value)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFileMode(%q) error: %v", tt.value, err)
			}
			if uint32(got) != tt.want {
				t.Fatalf("parseFileMode(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestCleanupStaleFiles(t *testing.T) {
	t.Run("removes existing files", func(t *testing.T) {
		dir := t.TempDir()
		f1 := filepath.Join(dir, "key.pem")
		f2 := filepath.Join(dir, "chain.pem")
		if err := os.WriteFile(f1, []byte("key"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f2, []byte("chain"), 0o600); err != nil {
			t.Fatal(err)
		}

		cleanupStaleFiles([]string{f1, f2})

		if _, err := os.Stat(f1); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed", f1)
		}
		if _, err := os.Stat(f2); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed", f2)
		}
	})

	t.Run("handles empty and missing paths gracefully", func(t *testing.T) {
		cleanupStaleFiles([]string{"", "  ", "/nonexistent/path/file.pem"})
	})

	t.Run("handles nil slice", func(t *testing.T) {
		cleanupStaleFiles(nil)
	})
}
