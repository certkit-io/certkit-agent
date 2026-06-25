package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	// requestTimeout caps the total time for a single API request, including
	// connection setup, TLS handshake, and reading the response headers.
	requestTimeout = 10 * time.Second

	// dialTimeout caps how long we wait to establish the TCP connection. When
	// the host is unreachable because of a network misconfiguration or a
	// firewall silently dropping packets
	dialTimeout = 5 * time.Second
)

// newAPITransport builds an http.Transport tuned to fail fast when the host is
// unreachable. tlsCfg may be nil to use the default TLS configuration.
func newAPITransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: requestTimeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// newHTTPClient returns the default HTTP client used for API requests.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: newAPITransport(nil),
	}
}

// doRequest performs req using client and translates low-level network and
// timeout failures into a clear, actionable error message.
func doRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, requestError(req.URL.Host, err)
	}
	return resp, nil
}

// requestError converts the cryptic errors returned by net/http (e.g.
// "context deadline exceeded (Client.Timeout exceeded while awaiting headers)")
// into a message that explains the likely cause. host is the target the request
// was sent to (the CertKit API or a keystore), so the operator can tell which
// hop is failing.
func requestError(host string, err error) error {
	if err == nil {
		return nil
	}

	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return fmt.Errorf("request to %s timed out. Ensure the agent can access the target host and there are no firewalls impacting communication", host)
	}

	return fmt.Errorf("could not reach %s. This is likely due to a network configuration error or a downstream host firewall issue: %w", host, err)
}
