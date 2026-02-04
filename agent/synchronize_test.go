package agent

import "testing"

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
