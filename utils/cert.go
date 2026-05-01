package utils

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

func GetCertificateSha1(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	certDER, err := firstCertificateDERFromPEM(data)
	if err != nil {
		return "", err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return "", fmt.Errorf("parse certificate: %w", err)
	}

	sum := sha1.Sum(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func DoesPfxContainSha1(path string, password string, expectedSha1 string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	return DoesPfxBytesContainSha1(data, password, expectedSha1)
}

func DoesPfxBytesContainSha1(data []byte, password string, expectedSha1 string) (bool, error) {
	if len(data) == 0 {
		return false, fmt.Errorf("empty PFX payload")
	}

	pemBlocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return false, fmt.Errorf("decode pfx: %w", err)
	}

	pfxContainsAtLeastOneCertificateBlock := false
	for _, block := range pemBlocks {
		if block == nil || block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false, fmt.Errorf("parse certificate from pfx: %w", err)
		}
		pfxContainsAtLeastOneCertificateBlock = true
		sum := sha1.Sum(cert.Raw)
		if strings.EqualFold(hex.EncodeToString(sum[:]), expectedSha1) {
			return true, nil
		}
	}

	if !pfxContainsAtLeastOneCertificateBlock {
		return false, fmt.Errorf("no certificate block found in PFX")
	}
	return false, nil
}

func firstCertificateDERFromPEM(data []byte) ([]byte, error) {
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			return block.Bytes, nil
		}
	}
	return nil, fmt.Errorf("no certificate block found in PEM")
}

func MergeKeyAndCert(keyPem string, certPem string) string {
	keyPem = ensureTrailingNewline(keyPem)
	certPem = strings.TrimSpace(certPem)
	if certPem != "" {
		certPem += "\n"
	}
	return keyPem + certPem
}

func ensureTrailingNewline(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	if strings.HasSuffix(value, "\n") {
		return value
	}
	return value + "\n"
}
