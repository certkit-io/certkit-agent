package crypto

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

// KeyToPKCS8DER converts a PEM-encoded private key (SEC1, PKCS1, or PKCS8) to PKCS8 DER bytes.
func KeyToPKCS8DER(keyPem string) ([]byte, error) {
	block, _ := pem.Decode([]byte(keyPem))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		ecKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key: %w", err)
		}
		return x509.MarshalPKCS8PrivateKey(ecKey)
	case "PRIVATE KEY":
		return block.Bytes, nil
	case "RSA PRIVATE KEY":
		rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		return x509.MarshalPKCS8PrivateKey(rsaKey)
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

// CreateJKS builds a JKS keystore from PEM certificate(s) and a PEM private key.
func CreateJKS(certPem, keyPem, password, alias string) ([]byte, error) {
	pkcs8Key, err := KeyToPKCS8DER(keyPem)
	if err != nil {
		return nil, fmt.Errorf("convert key to PKCS8: %w", err)
	}

	certs, err := parseCertificatesPEM(certPem)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM")
	}

	chain := make([]keystore.Certificate, len(certs))
	for i, cert := range certs {
		chain[i] = keystore.Certificate{
			Type:    "X509",
			Content: cert.Raw,
		}
	}

	if strings.TrimSpace(alias) == "" {
		alias = "certkit"
	}

	ks := keystore.New()
	entry := keystore.PrivateKeyEntry{
		CreationTime:     time.Now(),
		PrivateKey:       pkcs8Key,
		CertificateChain: chain,
	}

	pw := []byte(password)
	if err := ks.SetPrivateKeyEntry(alias, entry, pw); err != nil {
		return nil, fmt.Errorf("set private key entry: %w", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, pw); err != nil {
		return nil, fmt.Errorf("store keystore: %w", err)
	}

	return buf.Bytes(), nil
}

// GetCertificateSha1FromJks extracts the SHA1 fingerprint of the leaf certificate from a JKS keystore.
func GetCertificateSha1FromJks(data []byte, password string) (string, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(password)); err != nil {
		return "", fmt.Errorf("load keystore: %w", err)
	}

	for _, alias := range ks.Aliases() {
		if ks.IsPrivateKeyEntry(alias) {
			entry, err := ks.GetPrivateKeyEntry(alias, []byte(password))
			if err != nil {
				return "", fmt.Errorf("get private key entry %q: %w", alias, err)
			}
			if len(entry.CertificateChain) == 0 {
				continue
			}
			cert, err := x509.ParseCertificate(entry.CertificateChain[0].Content)
			if err != nil {
				return "", fmt.Errorf("parse certificate: %w", err)
			}
			sum := sha1.Sum(cert.Raw)
			return hex.EncodeToString(sum[:]), nil
		}
	}

	return "", fmt.Errorf("no private key entry found in keystore")
}

func parseCertificatesPEM(certPem string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	data := []byte(certPem)

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, cert)
	}

	return certs, nil
}
