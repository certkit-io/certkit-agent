//go:build linux

package agent

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeBundle(t *testing.T, path string, certs ...*x509.Certificate) {
	t.Helper()
	if err := os.WriteFile(path, []byte(pemEncodeCerts(certs...)), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
}

func TestFreshSystemRoots_SeesRootsInstalledAfterFirstLoad(t *testing.T) {
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.pem")
	t.Setenv("SSL_CERT_FILE", bundlePath)
	t.Setenv("SSL_CERT_DIR", filepath.Join(dir, "no-such-dir"))

	_, first := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	writeBundle(t, bundlePath, first)

	pool := freshSystemRoots()
	if pool == nil {
		t.Fatal("expected a pool from SSL_CERT_FILE")
	}
	if _, err := first.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("first root should verify against the fresh pool: %v", err)
	}

	// A root added after the first load is visible on the next load — the
	// point of reading fresh instead of using Go's once-per-process pool.
	_, second := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	writeBundle(t, bundlePath, first, second)

	pool = freshSystemRoots()
	if pool == nil {
		t.Fatal("expected a pool after re-reading the bundle")
	}
	if _, err := second.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("second root should verify after re-reading: %v", err)
	}
}

func TestFreshSystemRoots_ReadsCertDirectories(t *testing.T) {
	dir := t.TempDir()
	certsDir := filepath.Join(dir, "certs")
	if err := os.Mkdir(certsDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "no-such-bundle.pem"))
	t.Setenv("SSL_CERT_DIR", certsDir)

	_, root := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	writeBundle(t, filepath.Join(certsDir, "certkit-test.pem"), root)

	pool := freshSystemRoots()
	if pool == nil {
		t.Fatal("expected a pool from SSL_CERT_DIR")
	}
	if _, err := root.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Fatalf("anchor-directory root should verify: %v", err)
	}
}

func TestFreshSystemRoots_NothingReadableReturnsNil(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SSL_CERT_FILE", filepath.Join(dir, "missing.pem"))
	t.Setenv("SSL_CERT_DIR", filepath.Join(dir, "missing-dir"))

	if pool := freshSystemRoots(); pool != nil {
		t.Fatal("expected nil so Verify falls back to the cached system pool, not an empty pool")
	}
}
