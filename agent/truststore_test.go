package agent

import (
	"testing"
	"time"

	"github.com/certkit-io/certkit-agent/config"
)

func TestShouldCheckPrivateCa(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Minute)
	stale := now.Add(-privateCaRecheckInterval)
	beforeStart := now.Add(-2 * time.Hour)

	prevProcessStart := privateCaProcessStart
	privateCaProcessStart = now.Add(-time.Hour)
	t.Cleanup(func() { privateCaProcessStart = prevProcessStart })

	tests := []struct {
		name string
		ca   config.PrivateCAConfig
		want bool
	}{
		{
			name: "never verified",
			ca:   config.PrivateCAConfig{},
			want: true,
		},
		{
			name: "recently verified",
			ca:   config.PrivateCAConfig{LastStatus: caStatusTrusted, LastVerified: &recent},
			want: false,
		},
		{
			name: "recheck interval elapsed",
			ca:   config.PrivateCAConfig{LastStatus: caStatusTrusted, LastVerified: &stale},
			want: true,
		},
		{
			// A failed install must not fast-retry on every poll: it waits
			// for a server-side config change (which clears LastVerified) or
			// the normal recheck interval.
			name: "recent install failure",
			ca:   config.PrivateCAConfig{LastStatus: caStatusErrorInstall, LastVerified: &recent},
			want: false,
		},
		{
			// LastVerified persists in the config file, so after a restart it
			// predates process start: the CA must be re-verified even though
			// the recheck interval hasn't elapsed.
			name: "verified before process start",
			ca:   config.PrivateCAConfig{LastStatus: caStatusTrusted, LastVerified: &beforeStart},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldCheckPrivateCa(tt.ca, now); got != tt.want {
				t.Fatalf("shouldCheckPrivateCa(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
