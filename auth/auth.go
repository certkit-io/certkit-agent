package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/utils"
)

// ComputeBodySHA256Base64url hashes the exact bytes that will be sent.
// This helper reads req.Body and then restores it so the request can still be sent.
func ComputeBodySHA256Base64url(req *http.Request) (string, error) {
	if req.Body == nil {
		sum := sha256.Sum256(nil)
		return base64.RawURLEncoding.EncodeToString(sum[:]), nil
	}

	// Read all bytes
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return "", fmt.Errorf("read request body: %w", err)
	}
	// Restore body for later sending
	req.Body = io.NopCloser(bytes.NewReader(b))

	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// canonicalPathAndQuery returns a stable string of "path?query".
// We intentionally do NOT re-encode or sort query parameters; we use the request as built.
// That means the signer and verifier must both use the exact URL as sent.
func canonicalPathAndQuery(u *url.URL) string {
	if u == nil {
		return "/"
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		return path + "?" + u.RawQuery
	}
	return path
}

// canonicalHost returns the host to sign. If Host header is empty, uses URL host.
func canonicalHost(req *http.Request) string {
	h := strings.TrimSpace(req.Host)
	if h != "" {
		return strings.ToLower(h)
	}
	if req.URL != nil {
		return strings.ToLower(req.URL.Host)
	}
	return ""
}

// buildSigningString is the exact string that gets signed.
// Keep this stable across client/server.
func buildSigningString(method, pathQuery, host string, ts int64, bodyHash string) string {
	// Newline-delimited "key: value" format.
	// Avoid trailing spaces. Always use upper method and lower host.
	return strings.Join([]string{
		"method: " + strings.ToUpper(method),
		"path: " + pathQuery,
		"host: " + strings.ToLower(host),
		"ts: " + strconv.FormatInt(ts, 10),
		"body_sha256: " + bodyHash,
	}, "\n")
}

// SignRequest signs the request and sets headers.
// It adds:
// - X-Agent-Id
// - X-Agent-Timestamp
// - X-Agent-Content-SHA256
// - Authorization: AgentSig ...
//
// agentID should be your server-issued ID for this agent.
func SignRequest(req *http.Request, agentID string, agentVersion string, priv ed25519.PrivateKey, now time.Time) error {
	if req == nil {
		return fmt.Errorf("req is nil")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid ed25519 private key length: got %d", len(priv))
	}
	if agentID == "" {
		return fmt.Errorf("agentID is required")
	}
	if req.URL == nil {
		return fmt.Errorf("req.URL is nil")
	}

	// Timestamp (unix seconds)
	ts := now.UTC().Unix()

	bodyHash, err := ComputeBodySHA256Base64url(req)
	if err != nil {
		return err
	}

	pathQuery := canonicalPathAndQuery(req.URL)
	host := canonicalHost(req)
	if host == "" {
		return fmt.Errorf("missing host (req.Host and req.URL.Host both empty)")
	}

	signingString := buildSigningString(req.Method, pathQuery, host, ts, bodyHash)
	sig := ed25519.Sign(priv, []byte(signingString))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	machineId, err := utils.GetStableMachineID()
	if err != nil {
		return fmt.Errorf("get machine id: %w", err)
	}

	// Attach headers
	req.Header.Set("X-Agent-Id", agentID)
	req.Header.Set("X-Machine-Id", machineId)
	if agentVersion != "" {
		req.Header.Set("X-Agent-Version", agentVersion)
	}
	req.Header.Set("X-Agent-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Agent-Content-SHA256", bodyHash)

	// Include what we signed to help debugging/forward compatibility
	req.Header.Set("Authorization",
		fmt.Sprintf(
			`AgentSig agentId="%s", alg="ed25519", sig="%s", signed="method path host ts body_sha256"`,
			agentID, sigB64,
		),
	)

	return nil
}
