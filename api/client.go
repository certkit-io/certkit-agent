package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
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

	// maxRetries is how many more times a failed status update is tried before
	// its error is returned, waiting retryDelay before each retry;
	maxRetries = 10
	retryDelay = 6 * time.Second
)

// newAPITransport builds an http.Transport tuned to fail fast when the host is
// unreachable. tlsCfg may be nil to use the default TLS configuration.
func newAPITransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
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

// agentStopping closes when the agent is asked to stop. It stays nil, which
// never closes, until SetStopChannel is called.
var agentStopping <-chan struct{}

// SetStopChannel registers the channel that closes when the agent is asked to
// stop, so a status update that is waiting to retry gives up instead of
// holding up the shutdown.
func SetStopChannel(stopCh <-chan struct{}) {
	agentStopping = stopCh
}

// statusCodeError is returned when the server answers a status update with an
// unexpected HTTP status code, so shouldRetry can tell a rejected request from
// a server failure.
type statusCodeError struct {
	operation  string
	statusCode int
	body       []byte
}

func (e *statusCodeError) Error() string {
	return fmt.Sprintf("%s failed: status=%d body=%s", e.operation, e.statusCode, e.body)
}

// shouldRetry reports whether a failed status update is worth sending again.
// A 4xx response means the server rejected the request itself, and the same
// request would just be rejected again.
func shouldRetry(err error) bool {
	var statusErr *statusCodeError
	if errors.As(err, &statusErr) && statusErr.statusCode >= 400 && statusErr.statusCode < 500 {
		return false
	}
	return err != nil
}

// waitToRetry logs a failed status update and waits retryDelay before the
// caller tries it again. If the agent is asked to stop during the wait, it
// returns false right away and the caller gives up. retry numbers the retry
// about to be made, from 1.
func waitToRetry(name string, retry int, err error) bool {
	log.Printf("%s failed, retrying in %s (retry %d of %d): %v", name, retryDelay, retry, maxRetries, err)
	select {
	case <-time.After(retryDelay):
		return true
	case <-agentStopping:
		log.Printf("%s not retried: agent is stopping", name)
		return false
	}
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
