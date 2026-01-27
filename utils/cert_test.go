package utils

import "testing"

func TestMergeKeyAndCert(t *testing.T) {
	tests := []struct {
		name string
		key  string
		cert string
		want string
	}{
		{
			name: "key without newline cert with newlines",
			key:  "KEY",
			cert: "CERT\nINT\n",
			want: "KEY\nCERT\nINT\n",
		},
		{
			name: "key with newline cert trimmed",
			key:  "KEY\n",
			cert: "  CERT  ",
			want: "KEY\nCERT\n",
		},
		{
			name: "empty key",
			key:  "",
			cert: "CERT",
			want: "CERT\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeKeyAndCert(tt.key, tt.cert)
			if got != tt.want {
				t.Fatalf("MergeKeyAndCert() = %q, want %q", got, tt.want)
			}
		})
	}
}
