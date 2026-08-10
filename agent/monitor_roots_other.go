//go:build !linux

package agent

import "crypto/x509"

// Windows consults CryptoAPI on every verification (nil roots = platform
// verifier), so newly installed private CA roots are always visible and no
// fresh load is needed.
func freshSystemRoots() *x509.CertPool {
	return nil
}
