//go:build !windows && !linux

package agent

import (
	"fmt"
	"runtime"

	"github.com/certkit-io/certkit-agent/config"
)

func privateCaTrustStoreUnsupportedReason() string {
	return fmt.Sprintf("private CA trust store management is not supported on %s", runtime.GOOS)
}

func isRootCaTrusted(_ config.PrivateCAConfig) (bool, error) {
	return false, fmt.Errorf("private CA trust store management is not supported on %s", runtime.GOOS)
}

func installRootCa(_ config.PrivateCAConfig) error {
	return fmt.Errorf("private CA trust store management is not supported on %s", runtime.GOOS)
}
