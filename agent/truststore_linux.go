//go:build linux

package agent

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

// linuxTrustStore describes one distro family's OS trust store: where anchor
// certificates go and the command that rebuilds the system bundle from them.
type linuxTrustStore struct {
	anchorDir  string
	anchorExt  string
	updateCmd  string
	updateArgs []string
}

// A family matches only when both its anchor directory and its update command
// are present — both ship in that family's ca-certificates package. Matching
// on the pair is what keeps the families apart: SUSE's update-ca-certificates
// shares its name with Debian's but reads /etc/pki/trust/anchors, and an
// anchor directory alone doesn't prove the update tooling is installed
// (minimal container images).
var linuxTrustStores = []linuxTrustStore{
	{anchorDir: "/usr/local/share/ca-certificates", anchorExt: ".crt", updateCmd: "update-ca-certificates"},                           // Debian/Ubuntu/Alpine (only .crt files are picked up)
	{anchorDir: "/etc/pki/ca-trust/source/anchors", anchorExt: ".pem", updateCmd: "update-ca-trust", updateArgs: []string{"extract"}}, // RHEL/Fedora/Amazon Linux
	{anchorDir: "/etc/pki/trust/anchors", anchorExt: ".pem", updateCmd: "update-ca-certificates"},                                     // SUSE/openSUSE
	{anchorDir: "/etc/ca-certificates/trust-source/anchors", anchorExt: ".pem", updateCmd: "update-ca-trust"},                         // Arch
}

func detectTrustStore() *linuxTrustStore {
	for i := range linuxTrustStores {
		trustStore := &linuxTrustStores[i]
		if !dirExists(trustStore.anchorDir) {
			continue
		}
		if _, err := exec.LookPath(trustStore.updateCmd); err != nil {
			continue
		}
		return trustStore
	}
	return nil
}

func (ts *linuxTrustStore) anchorPath(caId string) string {
	return filepath.Join(ts.anchorDir, "certkit-"+caId+ts.anchorExt)
}

func privateCaTrustStoreUnsupportedReason() string {
	if detectTrustStore() != nil {
		return ""
	}
	return "no supported trust store found: no known anchor directory has its update command on PATH (is the ca-certificates package installed?)"
}

func isRootCaTrusted(ca config.PrivateCAConfig) (bool, error) {
	trustStore := detectTrustStore()
	if trustStore == nil {
		return false, fmt.Errorf("no supported trust store found")
	}
	anchorPath := trustStore.anchorPath(ca.Id)

	exists, err := utils.FileExists(anchorPath)
	if err != nil {
		return false, fmt.Errorf("stat anchor file %s: %w", anchorPath, err)
	}
	if !exists {
		return false, nil
	}

	data, err := os.ReadFile(anchorPath)
	if err != nil {
		return false, fmt.Errorf("read anchor file %s: %w", anchorPath, err)
	}

	// A malformed anchor is treated as not trusted so auto-install rewrites it.
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return false, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, nil
	}

	sum := sha256.Sum256(cert.Raw)
	return strings.EqualFold(hex.EncodeToString(sum[:]), ca.RootSHA256), nil
}

func installRootCa(ca config.PrivateCAConfig) error {
	trustStore := detectTrustStore()
	if trustStore == nil {
		return fmt.Errorf("no supported trust store found")
	}
	anchorPath := trustStore.anchorPath(ca.Id)

	log.Printf("Writing private CA root to %s", anchorPath)
	if err := utils.WriteFileAtomic(anchorPath, []byte(ca.RootCAPEM), 0o644); err != nil {
		return fmt.Errorf("write anchor file %s: %w", anchorPath, err)
	}

	cmd := exec.Command(trustStore.updateCmd, trustStore.updateArgs...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if output != "" {
		log.Printf("%s output:\n%s", trustStore.updateCmd, output)
	}
	if err != nil {
		if output != "" {
			return fmt.Errorf("%s failed: %w: %s", trustStore.updateCmd, err, output)
		}
		return fmt.Errorf("%s failed: %w", trustStore.updateCmd, err)
	}

	return nil
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
