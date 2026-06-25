package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// timeoutError is a net.Error whose Timeout() reports true, mimicking the
// errors net/http returns when a request exceeds its deadline.
type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return false }

func TestRequestErrorTranslatesTimeouts(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"context deadline", context.DeadlineExceeded},
		{"net timeout", &net.OpError{Op: "dial", Err: timeoutError{}}},
		{"wrapped client timeout", fmt.Errorf("Post %q: %w", "https://example", timeoutError{})},
	}

	const host = "keystore.example.com:8443"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := requestError(host, tc.err)
			if got == nil {
				t.Fatal("expected an error, got nil")
			}
			msg := got.Error()
			if !strings.Contains(msg, "timed out") || !strings.Contains(msg, "firewall") {
				t.Fatalf("timeout error not translated to a friendly message: %q", msg)
			}
			if !strings.Contains(msg, host) {
				t.Fatalf("timeout message should name the target host %q: %q", host, msg)
			}
			// The cryptic Go internals must not leak into the user-facing message.
			if strings.Contains(msg, "Client.Timeout") || strings.Contains(msg, "context deadline") {
				t.Fatalf("friendly message still leaks low-level detail: %q", msg)
			}
		})
	}
}

func TestRequestErrorPreservesNonTimeout(t *testing.T) {
	underlying := errors.New("connection refused")
	got := requestError("api.example.com:443", fmt.Errorf("dial tcp: %w", underlying))
	if got == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(got, underlying) {
		t.Fatalf("non-timeout error should wrap the underlying cause, got: %v", got)
	}
	if !strings.Contains(got.Error(), "api.example.com:443") {
		t.Fatalf("non-timeout message should name the target host: %v", got)
	}
}

func TestRequestErrorNil(t *testing.T) {
	if err := requestError("api.example.com:443", nil); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

// TestNewHTTPClientTimeoutIsShort guards against a regression where the agent
// would hang for tens of seconds against an unreachable host.
func TestNewHTTPClientTimeoutIsShort(t *testing.T) {
	if c := newHTTPClient(); c.Timeout > 15*time.Second {
		t.Fatalf("client timeout too long: %v", c.Timeout)
	}
}

// TestDoRequestReturnsFriendlyTimeout exercises the real client against a
// server that never responds, confirming a timeout yields the friendly message.
func TestDoRequestReturnsFriendlyTimeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-block // hang until the client gives up
	}))
	defer srv.Close()
	defer close(block)

	client := &http.Client{Timeout: 100 * time.Millisecond, Transport: newAPITransport(nil)}
	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	_, err = doRequest(client, req)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected friendly timeout message, got: %v", err)
	}
}
