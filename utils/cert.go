package utils

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
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
