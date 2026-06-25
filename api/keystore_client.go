package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

var (
	keystoreMu     sync.RWMutex
	keystoreClient *http.Client
	keystoreHost   string
)

// InitKeystoreClient creates a dedicated HTTP client for keystore communication.
// The client trusts only the provided CA certificate — not the system pool.
func InitKeystoreClient(host string, caCertPEM string) error {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caCertPEM)) {
		return fmt.Errorf("failed to parse keystore CA certificate PEM")
	}

	serverName, err := extractHostname(host)
	if err != nil {
		return fmt.Errorf("extract keystore hostname: %w", err)
	}

	tlsCfg := &tls.Config{
		RootCAs:    pool,
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
	}

	client := &http.Client{
		Timeout:   requestTimeout,
		Transport: newAPITransport(tlsCfg),
	}

	keystoreMu.Lock()
	defer keystoreMu.Unlock()
	keystoreClient = client
	keystoreHost = host
	return nil
}

// GetKeystoreClient returns the current keystore HTTP client, or nil if not configured.
func GetKeystoreClient() *http.Client {
	keystoreMu.RLock()
	defer keystoreMu.RUnlock()
	return keystoreClient
}

// ClearKeystoreClient removes the keystore HTTP client and closes its idle connections.
func ClearKeystoreClient() {
	keystoreMu.Lock()
	defer keystoreMu.Unlock()
	if keystoreClient != nil {
		keystoreClient.CloseIdleConnections()
	}
	keystoreClient = nil
	keystoreHost = ""
}

// GetKeystoreHost returns the configured keystore host.
func GetKeystoreHost() string {
	keystoreMu.RLock()
	defer keystoreMu.RUnlock()
	return keystoreHost
}

// extractHostname pulls just the hostname from a URL, host:port, or bare hostname.
func extractHostname(host string) (string, error) {
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return "", err
		}
		return u.Hostname(), nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h, nil
	}
	return host, nil
}
