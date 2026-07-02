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

const (
	debianAnchorDir = "/usr/local/share/ca-certificates"
	rhelAnchorDir   = "/etc/pki/ca-trust/source/anchors"
)

func privateCaTrustStoreUnsupportedReason() string {
	if dirExists(debianAnchorDir) || dirExists(rhelAnchorDir) {
		return ""
	}
	return fmt.Sprintf("no supported trust store found (neither %s nor %s exists)", debianAnchorDir, rhelAnchorDir)
}

func isRootCaTrusted(ca config.PrivateCAConfig) (bool, error) {
	anchorPath := anchorPathForCa(ca.Id)

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
	anchorPath := anchorPathForCa(ca.Id)

	updateCmdName := "update-ca-certificates"
	var updateCmdArgs []string
	if !dirExists(debianAnchorDir) {
		updateCmdName = "update-ca-trust"
		updateCmdArgs = []string{"extract"}
	}

	log.Printf("Writing private CA root to %s", anchorPath)
	if err := utils.WriteFileAtomic(anchorPath, []byte(ca.RootCAPEM), 0o644); err != nil {
		return fmt.Errorf("write anchor file %s: %w", anchorPath, err)
	}

	cmd := exec.Command(updateCmdName, updateCmdArgs...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if output != "" {
		log.Printf("%s output:\n%s", updateCmdName, output)
	}
	if err != nil {
		if output != "" {
			return fmt.Errorf("%s failed: %w: %s", updateCmdName, err, output)
		}
		return fmt.Errorf("%s failed: %w", updateCmdName, err)
	}

	return nil
}

func anchorPathForCa(caId string) string {
	if dirExists(debianAnchorDir) {
		return filepath.Join(debianAnchorDir, "certkit-"+caId+".crt")
	}
	return filepath.Join(rhelAnchorDir, "certkit-"+caId+".pem")
}

func dirExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}
