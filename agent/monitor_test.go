package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

func setupMonitorConfig(t *testing.T, monitors []config.DomainMonitorConfig) {
	t.Helper()
	previousConfig := config.CurrentConfig
	previousPath := config.CurrentPath
	t.Cleanup(func() {
		config.CurrentConfig = previousConfig
		config.CurrentPath = previousPath
	})
	config.CurrentPath = filepath.Join(t.TempDir(), "config.json")
	config.CurrentConfig = config.Config{DomainMonitors: monitors}
}

func pemEncodeCerts(certs ...*x509.Certificate) string {
	var builder strings.Builder
	for _, cert := range certs {
		builder.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}
	return builder.String()
}

// newSelfSignedCert generates a throwaway self-signed certificate. It cannot
// be trusted by the machine's real trust store, so untrusted-chain tests are
// deterministic regardless of what the host trusts.
func newSelfSignedCert(t *testing.T, dnsNames []string, ipAddresses []net.IP, notBefore, notAfter time.Time) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(0x0ABC),
		Subject:      pkix.Name{CommonName: "monitor-test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, parsed
}

// newCaSignedCert generates a throwaway CA and a leaf signed by it. The
// returned tls.Certificate serves both, leaf first.
func newCaSignedCert(t *testing.T, ipAddresses []net.IP) (tls.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	return newCaSignedCertValidFor(t, ipAddresses, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

// newCaSignedCertValidFor is newCaSignedCert with the leaf's validity window
// chosen by the caller. The CA is valid from before the leaf until tomorrow.
func newCaSignedCertValidFor(t *testing.T, ipAddresses []net.IP, leafNotBefore, leafNotAfter time.Time) (tls.Certificate, *x509.Certificate, *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "monitor-test-ca"},
		NotBefore:             leafNotBefore.Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDer, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDer)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "monitor-test-leaf"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ipAddresses,
	}
	leafDer, err := x509.CreateCertificate(rand.Reader, &leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDer)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{leafDer, caDer}, PrivateKey: leafKey}, leafCert, caCert
}

func startTLSListener(t *testing.T, cert tls.Certificate) int {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				c.Close()
			}(conn)
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

// startMutualTLSListener serves cert but requires a client certificate,
// mirroring SIP-TLS gateways: the server sends its certificate and then
// aborts the handshake because the agent presents no client certificate.
// TLS 1.2 is pinned so the abort happens before the client's handshake
// completes (under TLS 1.3 the client finishes first and only a later read
// fails).
func startMutualTLSListener(t *testing.T, cert tls.Certificate) int {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		MaxVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if tlsConn, ok := c.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				c.Close()
			}(conn)
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

func TestCheckDomainMonitor_ClientCertRequiredStillReportsChain(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	port := startMutualTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if !result.Success {
		t.Fatalf("expected success despite aborted handshake, got failure %q (flags %v)", result.FailureReason, result.ChainStatusFlags)
	}
	if result.ChainPem != pemEncodeCerts(leaf) {
		t.Fatal("expected ChainPem to carry the chain served before the handshake was aborted")
	}
	if result.Thumbprint == "" || result.Expires == "" {
		t.Fatal("expected leaf fields to be populated from the captured chain")
	}
	if result.RootInTrustStore == nil || !*result.RootInTrustStore {
		t.Fatalf("RootInTrustStore = %v, want true", result.RootInTrustStore)
	}
	// The monitoring handshake is the "modern" probe, and it was aborted.
	if result.Tls == nil || len(result.Tls.Probes) == 0 {
		t.Fatal("expected TLS details once a certificate arrived")
	}
	modern := result.Tls.Probes[0]
	if modern.Id != probeIdModern || modern.Succeeded || modern.Error == "" {
		t.Fatalf("modern probe = %+v, want a failed handshake with its error", modern)
	}
}

func TestCheckDomainMonitor_SelfSignedUntrusted(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	port := startTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, nil)

	if result.Success {
		t.Fatal("expected failure for untrusted self-signed certificate")
	}
	if result.FailureReason != failureX509ChainFailure {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureX509ChainFailure)
	}
	if result.ChainStatusFlags == nil || *result.ChainStatusFlags != chainFlagUntrustedRoot {
		t.Fatalf("ChainStatusFlags = %v, want %d", result.ChainStatusFlags, chainFlagUntrustedRoot)
	}
	if result.RootInTrustStore == nil || *result.RootInTrustStore {
		t.Fatalf("RootInTrustStore = %v, want false", result.RootInTrustStore)
	}
	if result.ChainPem != pemEncodeCerts(leaf) {
		t.Fatal("expected ChainPem to carry the served chain even when untrusted")
	}
}

func TestCheckDomainMonitor_TrustedViaProvidedRoots(t *testing.T) {
	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, notBefore, notAfter)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	port := startTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if !result.Success {
		t.Fatalf("expected success, got failure %q (flags %v)", result.FailureReason, result.ChainStatusFlags)
	}
	if result.FailureReason != "" {
		t.Fatalf("FailureReason = %q, want empty", result.FailureReason)
	}
	if result.ChainStatusFlags != nil {
		t.Fatalf("ChainStatusFlags = %d, want nil", *result.ChainStatusFlags)
	}
	if result.RootInTrustStore == nil || !*result.RootInTrustStore {
		t.Fatalf("RootInTrustStore = %v, want true", result.RootInTrustStore)
	}
	if result.ChainPem != pemEncodeCerts(leaf) {
		t.Fatal("expected ChainPem to carry the served chain")
	}

	sha1Sum := sha1.Sum(leaf.Raw)
	wantThumbprint := strings.ToUpper(hex.EncodeToString(sha1Sum[:]))
	if result.Thumbprint != wantThumbprint {
		t.Fatalf("Thumbprint = %q, want %q", result.Thumbprint, wantThumbprint)
	}
	sha256Sum := sha256.Sum256(leaf.Raw)
	wantSha256 := strings.ToUpper(hex.EncodeToString(sha256Sum[:]))
	if result.Sha256 != wantSha256 {
		t.Fatalf("Sha256 = %q, want %q", result.Sha256, wantSha256)
	}
	if result.SerialNumber != "0ABC" {
		t.Fatalf("SerialNumber = %q, want %q", result.SerialNumber, "0ABC")
	}
	if result.Expires != notAfter.UTC().Format(time.RFC3339) {
		t.Fatalf("Expires = %q, want %q", result.Expires, notAfter.UTC().Format(time.RFC3339))
	}
	if result.NotBefore != notBefore.UTC().Format(time.RFC3339) {
		t.Fatalf("NotBefore = %q, want %q", result.NotBefore, notBefore.UTC().Format(time.RFC3339))
	}
	if _, err := time.Parse(time.RFC3339, result.Timestamp); err != nil {
		t.Fatalf("Timestamp %q is not RFC3339: %v", result.Timestamp, err)
	}
}

func TestCheckDomainMonitor_HostnameMismatchShortCircuitsBeforeChain(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, []string{"wrong.internal"}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	port := startTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, nil)

	if result.Success {
		t.Fatal("expected failure for hostname mismatch")
	}
	// The certificate is also untrusted; CertificateDoesNotCoverDomain proves
	// the SAN failure still decides the result ahead of the chain failure,
	// even though the chain is now verified first.
	if result.FailureReason != failureCertificateDoesNotCoverDomain {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureCertificateDoesNotCoverDomain)
	}
	if result.ChainStatusFlags != nil {
		t.Fatalf("ChainStatusFlags = %d, want nil", *result.ChainStatusFlags)
	}
	if result.Thumbprint == "" || result.Expires == "" {
		t.Fatal("expected leaf fields to be populated on hostname mismatch")
	}
	if result.RootInTrustStore != nil {
		t.Fatalf("RootInTrustStore = %v, want nil on a hostname mismatch", *result.RootInTrustStore)
	}
	if result.ChainPem != pemEncodeCerts(leaf) {
		t.Fatal("expected ChainPem to carry the served chain on hostname mismatch")
	}
}

// A server hosting several sites on one address picks its certificate by SNI.
// The host name override goes out as SNI on the monitoring handshake and on
// every probe, and the certificate is judged against the override rather than
// the address dialed.
func TestCheckDomainMonitor_SniHostNameOverride(t *testing.T) {
	siteCert, siteLeaf := newSelfSignedCert(t, []string{"app.corp.local"}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	defaultCert, _ := newSelfSignedCert(t, []string{"default.corp.local"}, nil, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	var serverNamesLock sync.Mutex
	var serverNames []string
	port := startProbeListener(t, &tls.Config{
		// Called for every ClientHello, before the server judges the versions offered.
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverNamesLock.Lock()
			serverNames = append(serverNames, hello.ServerName)
			serverNamesLock.Unlock()
			return nil, nil
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "app.corp.local" {
				return &siteCert, nil
			}
			return &defaultCert, nil
		},
	})

	pool := x509.NewCertPool()
	pool.AddCert(siteLeaf)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port, SniHostName: "app.corp.local"}, pool)

	if !result.Success {
		t.Fatalf("expected success, got failure %q (flags %v)", result.FailureReason, result.ChainStatusFlags)
	}
	if result.ChainPem != pemEncodeCerts(siteLeaf) {
		t.Fatal("expected the certificate the server picked for the override")
	}

	serverNamesLock.Lock()
	sent := append([]string(nil), serverNames...)
	serverNamesLock.Unlock()
	if len(sent) != 1+len(monitorProbes) {
		t.Fatalf("server saw %d handshakes (%v), want the monitoring one and %d probes", len(sent), sent, len(monitorProbes))
	}
	for _, name := range sent {
		if name != "app.corp.local" {
			t.Fatalf("server names sent = %v, want app.corp.local on every handshake", sent)
		}
	}

	// The address alone gets the server's default certificate, which doesn't cover it.
	withoutOverride := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)
	if withoutOverride.FailureReason != failureCertificateDoesNotCoverDomain {
		t.Fatalf("FailureReason without the override = %q, want %q", withoutOverride.FailureReason, failureCertificateDoesNotCoverDomain)
	}
}

func TestCheckDomainMonitor_ExpiredCert(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	port := startTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if result.Success {
		t.Fatal("expected failure for expired certificate")
	}
	if result.FailureReason != failureX509ChainFailure {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureX509ChainFailure)
	}
	if result.ChainStatusFlags == nil || *result.ChainStatusFlags != chainFlagNotTimeValid {
		t.Fatalf("ChainStatusFlags = %v, want %d", result.ChainStatusFlags, chainFlagNotTimeValid)
	}
	if result.RootInTrustStore != nil {
		t.Fatalf("RootInTrustStore = %v, want nil for a non-trust chain failure", *result.RootInTrustStore)
	}
}

func TestCheckDomainMonitor_ClosedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, nil)

	if result.Success {
		t.Fatal("expected failure for closed port")
	}
	if result.FailureReason != failureUnableToRetrieveCertificate {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureUnableToRetrieveCertificate)
	}
	if result.Thumbprint != "" || result.Expires != "" || result.ChainStatusFlags != nil {
		t.Fatal("expected empty certificate fields for closed port")
	}
	if result.ChainPem != "" || result.RootInTrustStore != nil {
		t.Fatal("expected no chain data for closed port")
	}
	if result.Tls != nil {
		t.Fatal("expected no TLS details for closed port")
	}
	if result.Timestamp == "" {
		t.Fatal("expected timestamp to be set")
	}
}

func TestCheckDomainMonitor_NonTLSListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, nil)

	if result.Success {
		t.Fatal("expected failure for non-TLS listener")
	}
	if result.FailureReason != failureUnableToRetrieveCertificate {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureUnableToRetrieveCertificate)
	}
}

func TestCheckDomainMonitor_ServedChainReportedInOrder(t *testing.T) {
	serverCert, leaf, ca := newCaSignedCert(t, []net.IP{net.ParseIP("127.0.0.1")})

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	port := startTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if !result.Success {
		t.Fatalf("expected success, got failure %q (flags %v)", result.FailureReason, result.ChainStatusFlags)
	}
	if result.RootInTrustStore == nil || !*result.RootInTrustStore {
		t.Fatalf("RootInTrustStore = %v, want true", result.RootInTrustStore)
	}
	if result.ChainPem != pemEncodeCerts(leaf, ca) {
		t.Fatal("expected ChainPem to carry the served chain leaf-first")
	}
}

func TestCheckDomainMonitor_ReportsTlsDetailsOnSuccess(t *testing.T) {
	serverCert, leaf, ca := newCaSignedCert(t, []net.IP{net.ParseIP("127.0.0.1")})

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	port := startTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if !result.Success {
		t.Fatalf("expected success, got failure %q (flags %v)", result.FailureReason, result.ChainStatusFlags)
	}
	if result.Tls == nil {
		t.Fatal("expected TLS details")
	}
	if result.Tls.RemoteIp != "127.0.0.1" {
		t.Fatalf("RemoteIp = %q, want 127.0.0.1", result.Tls.RemoteIp)
	}
	if result.Tls.VerifiedChainPem != pemEncodeCerts(leaf, ca) {
		t.Fatal("expected VerifiedChainPem to run leaf to root")
	}

	wantIds := []string{probeIdModern, probeIdX25519MLKEM768, probeIdSecP256r1MLKEM768, probeIdSecP384r1MLKEM1024, probeIdTls12, probeIdLegacy}
	if len(result.Tls.Probes) != len(wantIds) {
		t.Fatalf("len(Probes) = %d, want %d", len(result.Tls.Probes), len(wantIds))
	}
	for i, id := range wantIds {
		if result.Tls.Probes[i].Id != id {
			t.Fatalf("Probes[%d].Id = %q, want %q", i, result.Tls.Probes[i].Id, id)
		}
	}

	modern := result.Tls.Probes[0]
	if !modern.Succeeded || modern.Version != tls.VersionTLS13 || modern.CipherSuite == 0 || modern.CurveId == 0 {
		t.Fatalf("modern probe = %+v, want a TLS 1.3 handshake with its suite and group", modern)
	}
}

func TestVerifiedChainForReport_TrustedIntermediate(t *testing.T) {
	now := time.Now()
	var certs []*x509.Certificate
	var parentKey *ecdsa.PrivateKey
	for i, name := range []string{"report-root", "report-intermediate", "report-leaf"} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(int64(i + 1)),
			Subject:               pkix.Name{CommonName: name},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(365 * 24 * time.Hour),
			IsCA:                  i < 2,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
		}
		if template.IsCA {
			template.KeyUsage |= x509.KeyUsageCertSign
		} else {
			template.NotAfter = now.Add(24 * time.Hour)
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		parent, signer := template, key
		if i > 0 {
			parent, signer = certs[i-1], parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
		parentKey = key
	}
	root, intermediate, leaf := certs[0], certs[1], certs[2]
	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediate)

	for _, tt := range []struct {
		name              string
		trustRoot         bool
		trustIntermediate bool
		expired           bool
		wrongUsage        bool
		wantError         bool
		want              string
	}{
		{name: "both trusted", trustRoot: true, trustIntermediate: true, want: pemEncodeCerts(leaf, intermediate, root)},
		{name: "root only", trustRoot: true, want: pemEncodeCerts(leaf, intermediate, root)},
		{name: "intermediate only", trustIntermediate: true, want: pemEncodeCerts(leaf, intermediate)},
		{name: "neither trusted", wantError: true},
		{name: "expired leaf", trustRoot: true, trustIntermediate: true, expired: true, wantError: true, want: pemEncodeCerts(leaf, intermediate, root)},
		{name: "wrong usage", trustRoot: true, trustIntermediate: true, wrongUsage: true, wantError: true, want: pemEncodeCerts(leaf, intermediate, root)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			roots := x509.NewCertPool()
			if tt.trustRoot {
				roots.AddCert(root)
			}
			if tt.trustIntermediate {
				roots.AddCert(intermediate)
			}
			options := x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now}
			if tt.expired {
				options.CurrentTime = now.Add(48 * time.Hour)
			}
			if tt.wrongUsage {
				options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			}
			chains, err := leaf.Verify(options)
			if (err != nil) != tt.wantError {
				t.Fatalf("Verify error = %v, wantError = %v", err, tt.wantError)
			}
			reported := verifiedChainForReport(leaf, options, chains, err)
			if pemEncodeCerts(reported...) != tt.want {
				t.Fatalf("reported %d certificates; expected the complete verified path when available", len(reported))
			}
		})
	}
}

// The chain is verified before the hostname check, so the panels can show its
// trust status even when the name doesn't match.
func TestCheckDomainMonitor_ReportsVerifiedChainOnHostnameMismatch(t *testing.T) {
	serverCert, leaf, ca := newCaSignedCert(t, []net.IP{net.ParseIP("10.0.0.1")})

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	port := startTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if result.FailureReason != failureCertificateDoesNotCoverDomain {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureCertificateDoesNotCoverDomain)
	}
	if result.ChainStatusFlags != nil || result.RootInTrustStore != nil {
		t.Fatal("expected no chain fields on a hostname mismatch")
	}
	if result.Tls == nil || result.Tls.VerifiedChainPem != pemEncodeCerts(leaf, ca) {
		t.Fatal("expected VerifiedChainPem on a hostname mismatch")
	}
}

func TestCheckDomainMonitor_NoVerifiedChainWhenUntrusted(t *testing.T) {
	serverCert, _, _ := newCaSignedCert(t, []net.IP{net.ParseIP("127.0.0.1")})
	port := startTLSListener(t, serverCert)

	// An empty pool trusts nothing, whatever this machine's trust store holds.
	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, x509.NewCertPool())

	if result.FailureReason != failureX509ChainFailure {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureX509ChainFailure)
	}
	if result.Tls == nil {
		t.Fatal("expected TLS details for a chain failure")
	}
	if result.Tls.VerifiedChainPem != "" {
		t.Fatal("expected no VerifiedChainPem for an untrusted chain")
	}
}

// An expired leaf from a trusted CA still reports the path to that CA, so the
// server shows "expired" rather than "not trusted". The result fields are the
// same as before.
func TestCheckDomainMonitor_ExpiredLeafStillReportsVerifiedChain(t *testing.T) {
	serverCert, leaf, ca := newCaSignedCertValidFor(t, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	port := startTLSListener(t, serverCert)

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if result.FailureReason != failureX509ChainFailure {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureX509ChainFailure)
	}
	if result.ChainStatusFlags == nil || *result.ChainStatusFlags != chainFlagNotTimeValid {
		t.Fatalf("ChainStatusFlags = %v, want %d", result.ChainStatusFlags, chainFlagNotTimeValid)
	}
	if result.RootInTrustStore != nil {
		t.Fatalf("RootInTrustStore = %v, want nil for a non-trust chain failure", *result.RootInTrustStore)
	}
	if result.Tls == nil || result.Tls.VerifiedChainPem != pemEncodeCerts(leaf, ca) {
		t.Fatal("expected VerifiedChainPem for an expired leaf from a trusted CA")
	}
}

// A certificate without serverAuth from a trusted CA reports the path too;
// the server judges the usage itself.
func TestCheckDomainMonitor_WrongUsageStillReportsVerifiedChain(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "monitor-test-client-auth"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	port := startTLSListener(t, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key})

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if result.FailureReason != failureX509ChainFailure {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureX509ChainFailure)
	}
	if result.ChainStatusFlags == nil || *result.ChainStatusFlags != chainFlagNotValidForUsage {
		t.Fatalf("ChainStatusFlags = %v, want %d", result.ChainStatusFlags, chainFlagNotValidForUsage)
	}
	if result.Tls == nil || result.Tls.VerifiedChainPem != pemEncodeCerts(leaf) {
		t.Fatal("expected VerifiedChainPem for a trusted certificate with the wrong usage")
	}
}

// Without a certificate there is nothing to show, so no probe connections
// are made at all.
func TestCheckDomainMonitor_NoCertificateMeansNoProbes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	var accepted atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conn.Close()
		}
	}()

	port := listener.Addr().(*net.TCPAddr).Port

	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, nil)

	if result.FailureReason != failureUnableToRetrieveCertificate {
		t.Fatalf("FailureReason = %q, want %q", result.FailureReason, failureUnableToRetrieveCertificate)
	}
	if result.Tls != nil {
		t.Fatal("expected no TLS details without a certificate")
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("accepted %d connections, want only the monitoring one", got)
	}
}

// The server reads these exact field names (AgentApiController's TlsObservation).
func TestDomainMonitoringResultUpdate_TlsWireFormat(t *testing.T) {
	result := api.DomainMonitoringResultUpdate{
		DomainId: "d1",
		Tls: &api.MonitorTlsDetails{
			RemoteIp: "10.0.4.20",
			Probes: []api.MonitorTlsProbe{
				{Id: probeIdModern, Succeeded: true, Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, CurveId: uint16(tls.X25519MLKEM768)},
				{Id: probeIdLegacy, Error: "remote error: tls: protocol version not supported"},
			},
		},
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want := `"tls":{"remote_ip":"10.0.4.20","probes":[` +
		`{"id":"modern","succeeded":true,"version":772,"cipher_suite":4865,"curve_id":4588},` +
		`{"id":"legacy","succeeded":false,"error":"remote error: tls: protocol version not supported"}]}`
	if !strings.Contains(string(encoded), want) {
		t.Fatalf("encoded = %s, want it to contain %s", encoded, want)
	}

	withoutTls, err := json.Marshal(api.DomainMonitoringResultUpdate{DomainId: "d1"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(withoutTls), `"tls"`) {
		t.Fatalf("encoded = %s, want no tls field", withoutTls)
	}
}

// The server sends null for a host without an override, and compares the
// override the agent echoes back on each poll (AgentApiController's poll diff).
func TestPollDomainMonitor_SniHostNameWireFormat(t *testing.T) {
	var monitor api.PollResponseDomainMonitor
	response := `{"domain_id":"d1","domain_name":"10.0.4.20","port":443,"check_requested_date":null,"sni_host_name":null}`
	if err := json.Unmarshal([]byte(response), &monitor); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if monitor.SniHostName != "" {
		t.Fatalf("SniHostName = %q, want empty for null", monitor.SniHostName)
	}

	encoded, err := json.Marshal(api.PollRequestDomainMonitor{DomainId: "d1", DomainName: "10.0.4.20", Port: 443, SniHostName: "app.corp.local"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"sni_host_name":"app.corp.local"`) {
		t.Fatalf("encoded = %s, want it to carry sni_host_name", encoded)
	}
}

func TestEncodeChainPem_Caps(t *testing.T) {
	_, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))

	if got := encodeChainPem([]*x509.Certificate{leaf}); got != pemEncodeCerts(leaf) {
		t.Fatal("expected a small chain to encode as its PEM")
	}

	tooMany := make([]*x509.Certificate, chainPemMaxCerts+1)
	for i := range tooMany {
		tooMany[i] = leaf
	}
	if got := encodeChainPem(tooMany); got != "" {
		t.Fatalf("encodeChainPem(%d certs) = %d bytes, want empty", len(tooMany), len(got))
	}

	// A single certificate bloated past the byte cap via a huge SAN list:
	// each name adds ~108 PEM bytes, so 3000 names is ~326KB.
	names := make([]string, 3000)
	for i := range names {
		names[i] = fmt.Sprintf("host%04d.%s.internal", i, strings.Repeat("a", 60))
	}
	_, bigLeaf := newSelfSignedCert(t, names, nil, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if got := encodeChainPem([]*x509.Certificate{bigLeaf}); got != "" {
		t.Fatalf("encodeChainPem(oversized cert) = %d bytes, want empty", len(got))
	}
}

func TestShouldCheckMonitor(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	recent := now.Add(-time.Hour)
	stale := now.Add(-9 * time.Hour)

	tests := []struct {
		name    string
		monitor config.DomainMonitorConfig
		want    bool
	}{
		{"never checked", config.DomainMonitorConfig{}, true},
		{"recheck interval elapsed", config.DomainMonitorConfig{LastChecked: &stale}, true},
		{"recently checked", config.DomainMonitorConfig{LastChecked: &recent}, false},
		{"pending check-now", config.DomainMonitorConfig{LastChecked: &recent, PendingCheckNow: "2026-07-06T11:59:00Z"}, true},
		{"check-now already honored", config.DomainMonitorConfig{LastChecked: &recent, PendingCheckNow: "2026-07-06T11:59:00Z", LastCheckNowHonored: "2026-07-06T11:59:00Z"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldCheckMonitor(tt.monitor, now); got != tt.want {
				t.Fatalf("shouldCheckMonitor() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestApplyDomainMonitorUpdates_AddsNewMonitor(t *testing.T) {
	setupMonitorConfig(t, nil)

	applyDomainMonitorUpdates([]api.PollResponseDomainMonitor{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443},
	})

	monitors := config.CurrentConfig.DomainMonitors
	if len(monitors) != 1 {
		t.Fatalf("len(monitors) = %d, want 1", len(monitors))
	}
	if monitors[0].DomainName != "db01.corp.local" || monitors[0].Port != 8443 {
		t.Fatalf("monitor = %+v, want db01.corp.local:8443", monitors[0])
	}
	if monitors[0].LastChecked != nil {
		t.Fatal("new monitor should have nil LastChecked so it is checked immediately")
	}
}

func TestApplyDomainMonitorUpdates_NameChangeResetsLastChecked(t *testing.T) {
	checked := time.Now().UTC()
	setupMonitorConfig(t, []config.DomainMonitorConfig{
		{DomainId: "d1", DomainName: "old.corp.local", Port: 8443, LastChecked: &checked},
	})

	applyDomainMonitorUpdates([]api.PollResponseDomainMonitor{
		{DomainId: "d1", DomainName: "new.corp.local", Port: 8443},
	})

	monitor := config.CurrentConfig.DomainMonitors[0]
	if monitor.DomainName != "new.corp.local" {
		t.Fatalf("DomainName = %q, want new.corp.local", monitor.DomainName)
	}
	if monitor.LastChecked != nil {
		t.Fatal("name change should reset LastChecked")
	}
}

func TestApplyDomainMonitorUpdates_PortChangeResetsLastChecked(t *testing.T) {
	checked := time.Now().UTC()
	setupMonitorConfig(t, []config.DomainMonitorConfig{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443, LastChecked: &checked},
	})

	applyDomainMonitorUpdates([]api.PollResponseDomainMonitor{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 9443},
	})

	monitor := config.CurrentConfig.DomainMonitors[0]
	if monitor.Port != 9443 {
		t.Fatalf("Port = %d, want 9443", monitor.Port)
	}
	if monitor.LastChecked != nil {
		t.Fatal("port change should reset LastChecked")
	}
}

func TestApplyDomainMonitorUpdates_SniHostNameChangeResetsLastChecked(t *testing.T) {
	checked := time.Now().UTC()
	setupMonitorConfig(t, []config.DomainMonitorConfig{
		{DomainId: "d1", DomainName: "10.0.4.20", Port: 443, LastChecked: &checked},
	})

	applyDomainMonitorUpdates([]api.PollResponseDomainMonitor{
		{DomainId: "d1", DomainName: "10.0.4.20", Port: 443, SniHostName: "app.corp.local"},
	})

	monitor := config.CurrentConfig.DomainMonitors[0]
	if monitor.SniHostName != "app.corp.local" {
		t.Fatalf("SniHostName = %q, want app.corp.local", monitor.SniHostName)
	}
	if monitor.LastChecked != nil {
		t.Fatal("host name override change should reset LastChecked")
	}
}

func TestApplyDomainMonitorUpdates_UnchangedPreservesLastChecked(t *testing.T) {
	checked := time.Now().UTC()
	setupMonitorConfig(t, []config.DomainMonitorConfig{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443, LastChecked: &checked, LastCheckNowHonored: "2026-07-06T11:00:00Z"},
	})

	applyDomainMonitorUpdates([]api.PollResponseDomainMonitor{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443},
	})

	monitor := config.CurrentConfig.DomainMonitors[0]
	if monitor.LastChecked == nil || !monitor.LastChecked.Equal(checked) {
		t.Fatalf("LastChecked = %v, want %v", monitor.LastChecked, checked)
	}
	if monitor.LastCheckNowHonored != "2026-07-06T11:00:00Z" {
		t.Fatalf("LastCheckNowHonored = %q, want preserved", monitor.LastCheckNowHonored)
	}
}

func TestApplyDomainMonitorUpdates_RemovesUnassignedMonitor(t *testing.T) {
	setupMonitorConfig(t, []config.DomainMonitorConfig{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443},
		{DomainId: "d2", DomainName: "db02.corp.local", Port: 8443},
	})

	applyDomainMonitorUpdates([]api.PollResponseDomainMonitor{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443},
	})

	monitors := config.CurrentConfig.DomainMonitors
	if len(monitors) != 1 {
		t.Fatalf("len(monitors) = %d, want 1", len(monitors))
	}
	if monitors[0].DomainId != "d1" {
		t.Fatalf("DomainId = %q, want d1", monitors[0].DomainId)
	}
}

func TestApplyDomainMonitorUpdates_NilListClearsAllMonitors(t *testing.T) {
	setupMonitorConfig(t, []config.DomainMonitorConfig{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443},
	})

	applyDomainMonitorUpdates(nil)

	if len(config.CurrentConfig.DomainMonitors) != 0 {
		t.Fatalf("len(monitors) = %d, want 0", len(config.CurrentConfig.DomainMonitors))
	}
}

func TestApplyDomainMonitorUpdates_CheckNowDateStoredWithoutResettingLastChecked(t *testing.T) {
	checked := time.Now().UTC()
	setupMonitorConfig(t, []config.DomainMonitorConfig{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443, LastChecked: &checked},
	})

	applyDomainMonitorUpdates([]api.PollResponseDomainMonitor{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443, CheckRequestedDate: "2026-07-06T14:03:22Z"},
	})

	monitor := config.CurrentConfig.DomainMonitors[0]
	if monitor.PendingCheckNow != "2026-07-06T14:03:22Z" {
		t.Fatalf("PendingCheckNow = %q, want the check_requested_date", monitor.PendingCheckNow)
	}
	if monitor.LastChecked == nil || !monitor.LastChecked.Equal(checked) {
		t.Fatalf("LastChecked = %v, want preserved", monitor.LastChecked)
	}
}

func TestStampMonitorsChecked_StampsOnlyReportedMonitors(t *testing.T) {
	setupMonitorConfig(t, []config.DomainMonitorConfig{
		{DomainId: "d1", DomainName: "db01.corp.local", Port: 8443, PendingCheckNow: "2026-07-06T14:03:22Z"},
		{DomainId: "d2", DomainName: "db02.corp.local", Port: 8443},
	})

	stampMonitorsChecked([]api.DomainMonitoringResultUpdate{{DomainId: "d1"}})

	monitors := config.CurrentConfig.DomainMonitors
	if monitors[0].LastChecked == nil {
		t.Fatal("reported monitor should have LastChecked set")
	}
	if monitors[0].LastCheckNowHonored != "2026-07-06T14:03:22Z" {
		t.Fatalf("LastCheckNowHonored = %q, want the pending check-now date", monitors[0].LastCheckNowHonored)
	}
	if monitors[1].LastChecked != nil {
		t.Fatal("unreported monitor should not be stamped")
	}
}

func TestFormatIssuerDN(t *testing.T) {
	tests := []struct {
		name   string
		issuer pkix.Name
		want   string
	}{
		{
			name: "all components",
			issuer: pkix.Name{
				CommonName:         "Acme Internal Issuing CA R1",
				OrganizationalUnit: []string{"PKI"},
				Organization:       []string{"Acme Internal"},
				Locality:           []string{"Springfield"},
				Province:           []string{"IL"},
				Country:            []string{"US"},
			},
			want: "CN=Acme Internal Issuing CA R1, OU=PKI, O=Acme Internal, L=Springfield, S=IL, C=US",
		},
		{
			name:   "cn and country only",
			issuer: pkix.Name{CommonName: "Root", Country: []string{"US"}},
			want:   "CN=Root, C=US",
		},
		{
			name:   "empty",
			issuer: pkix.Name{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatIssuerDN(tt.issuer); got != tt.want {
				t.Fatalf("formatIssuerDN() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatSerialNumber(t *testing.T) {
	tests := []struct {
		name   string
		serial *big.Int
		want   string
	}{
		{"even length", big.NewInt(0xFF), "FF"},
		{"odd length padded", big.NewInt(0xABC), "0ABC"},
		{"zero", big.NewInt(0), "00"},
		{"negative uses absolute value", big.NewInt(-0xABC), "0ABC"},
		{"nil", nil, "00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatSerialNumber(tt.serial); got != tt.want {
				t.Fatalf("formatSerialNumber() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMonitorKeyUsages(t *testing.T) {
	rdpOnly := &x509.Certificate{UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidRemoteDesktopAuthentication}}
	serverAuthAndRdp := &x509.Certificate{
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidRemoteDesktopAuthentication},
	}
	serverAuthOnly := &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	clientAuthOnly := &x509.Certificate{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}

	tests := []struct {
		name string
		port int
		leaf *x509.Certificate
		want x509.ExtKeyUsage
	}{
		{"rdp eku on rdp port", rdpPort, rdpOnly, x509.ExtKeyUsageAny},
		{"rdp eku on another port", 443, rdpOnly, x509.ExtKeyUsageServerAuth},
		{"server auth and rdp eku on rdp port", rdpPort, serverAuthAndRdp, x509.ExtKeyUsageServerAuth},
		{"server auth on rdp port", rdpPort, serverAuthOnly, x509.ExtKeyUsageServerAuth},
		{"client auth on rdp port", rdpPort, clientAuthOnly, x509.ExtKeyUsageServerAuth},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := monitorKeyUsages(tt.port, tt.leaf)
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("monitorKeyUsages() = %v, want [%v]", got, tt.want)
			}
		})
	}
}

// AD CS Remote Desktop templates issue only the RDP EKU. Such a certificate
// must verify on the RDP port and still fail for usage on any other port.
func TestMonitorKeyUsages_RdpOnlyCertificateVerifies(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "monitor-test-rdp"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{oidRemoteDesktopAuthentication},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: monitorKeyUsages(rdpPort, leaf)}); err != nil {
		t.Fatalf("expected the RDP-only certificate to verify on the RDP port: %v", err)
	}

	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: monitorKeyUsages(443, leaf)})
	var invalidErr x509.CertificateInvalidError
	if !errors.As(err, &invalidErr) || invalidErr.Reason != x509.IncompatibleUsage {
		t.Fatalf("expected IncompatibleUsage on port 443, got %v", err)
	}
}
