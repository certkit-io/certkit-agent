package agent

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

// startProbeListener serves TLS with serverConfig, so a test can restrict the
// versions, groups and suites the server accepts.
func startProbeListener(t *testing.T, serverConfig *tls.Config) int {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
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

// newSelfSignedRSACert generates a throwaway self-signed RSA certificate:
// static RSA key exchange needs an RSA key.
func newSelfSignedRSACert(t *testing.T, ipAddresses []net.IP) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(0x0DEF),
		Subject:      pkix.Name{CommonName: "monitor-test-rsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

// checkProbedMonitor runs the monitoring check against a local server with a
// certificate the check trusts and returns the reported probes.
func checkProbedMonitor(t *testing.T, serverConfig *tls.Config, trusted *x509.Certificate) []api.MonitorTlsProbe {
	t.Helper()

	pool := x509.NewCertPool()
	pool.AddCert(trusted)

	port := startProbeListener(t, serverConfig)
	result := checkDomainMonitor(config.DomainMonitorConfig{DomainId: "d1", DomainName: "127.0.0.1", Port: port}, pool)

	if !result.Success {
		t.Fatalf("expected the monitoring check to succeed, got failure %q (flags %v)", result.FailureReason, result.ChainStatusFlags)
	}
	if result.Tls == nil {
		t.Fatal("expected TLS details")
	}
	return result.Tls.Probes
}

func findProbe(t *testing.T, probes []api.MonitorTlsProbe, id string) api.MonitorTlsProbe {
	t.Helper()
	for _, probe := range probes {
		if probe.Id == id {
			return probe
		}
	}
	t.Fatalf("no probe with id %q in %+v", id, probes)
	return api.MonitorTlsProbe{}
}

func TestRunMonitorProbes_HybridOnlyServer(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	probes := checkProbedMonitor(t, &tls.Config{
		Certificates:     []tls.Certificate{serverCert},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}, leaf)

	modern := findProbe(t, probes, probeIdModern)
	if !modern.Succeeded || modern.Version != tls.VersionTLS13 || modern.CurveId != uint16(tls.X25519MLKEM768) {
		t.Fatalf("modern probe = %+v, want TLS 1.3 with X25519MLKEM768", modern)
	}

	hybrid := findProbe(t, probes, probeIdX25519MLKEM768)
	if !hybrid.Succeeded || hybrid.CurveId != uint16(tls.X25519MLKEM768) {
		t.Fatalf("x25519mlkem768 probe = %+v, want success with curve 4588", hybrid)
	}

	for _, id := range []string{probeIdSecP256r1MLKEM768, probeIdSecP384r1MLKEM1024} {
		probe := findProbe(t, probes, id)
		if probe.Succeeded || probe.Error == "" {
			t.Fatalf("%s probe = %+v, want a failed handshake with its error", id, probe)
		}
	}
}

// The monitoring handshake doesn't offer SecP384r1MLKEM1024 (browsers don't),
// so only its own probe finds it.
func TestRunMonitorProbes_SecP384r1MLKEM1024Server(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	probes := checkProbedMonitor(t, &tls.Config{
		Certificates:     []tls.Certificate{serverCert},
		CurvePreferences: []tls.CurveID{tls.SecP384r1MLKEM1024, tls.X25519},
	}, leaf)

	modern := findProbe(t, probes, probeIdModern)
	if !modern.Succeeded || modern.CurveId != uint16(tls.X25519) {
		t.Fatalf("modern probe = %+v, want X25519", modern)
	}

	hybrid := findProbe(t, probes, probeIdSecP384r1MLKEM1024)
	if !hybrid.Succeeded || hybrid.Version != tls.VersionTLS13 || hybrid.CurveId != uint16(tls.SecP384r1MLKEM1024) {
		t.Fatalf("secp384r1mlkem1024 probe = %+v, want TLS 1.3 with curve 4589", hybrid)
	}

	for _, id := range []string{probeIdX25519MLKEM768, probeIdSecP256r1MLKEM768} {
		if findProbe(t, probes, id).Succeeded {
			t.Fatalf("expected the %s probe to fail", id)
		}
	}
}

func TestRunMonitorProbes_Tls12OnlyServer(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	probes := checkProbedMonitor(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MaxVersion:   tls.VersionTLS12,
	}, leaf)

	modern := findProbe(t, probes, probeIdModern)
	if !modern.Succeeded || modern.Version != tls.VersionTLS12 {
		t.Fatalf("modern probe = %+v, want TLS 1.2", modern)
	}

	tls12 := findProbe(t, probes, probeIdTls12)
	if !tls12.Succeeded || tls12.Version != tls.VersionTLS12 || tls12.CipherSuite == 0 || tls12.CurveId == 0 {
		t.Fatalf("tls12 probe = %+v, want an ECDHE handshake on TLS 1.2", tls12)
	}

	for _, id := range []string{probeIdX25519MLKEM768, probeIdSecP256r1MLKEM768, probeIdSecP384r1MLKEM1024, probeIdLegacy} {
		if findProbe(t, probes, id).Succeeded {
			t.Fatalf("expected the %s probe to fail", id)
		}
	}
}

// TLS 1.3 works for the monitoring handshake; TLS 1.2 only offers static RSA
// key exchange, which the tls12 probe must still find.
func TestRunMonitorProbes_RsaKeyExchangeOnTls12(t *testing.T) {
	serverCert, leaf := newSelfSignedRSACert(t, []net.IP{net.ParseIP("127.0.0.1")})

	probes := checkProbedMonitor(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
	}, leaf)

	tls12 := findProbe(t, probes, probeIdTls12)
	if !tls12.Succeeded || tls12.CipherSuite != tls.TLS_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("tls12 probe = %+v, want TLS_RSA_WITH_AES_128_GCM_SHA256", tls12)
	}
	if tls12.CurveId != 0 {
		t.Fatalf("tls12 probe CurveId = %d, want 0 for static RSA key exchange", tls12.CurveId)
	}
}

func TestRunMonitorProbes_LegacyTlsServer(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	probes := checkProbedMonitor(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS10,
	}, leaf)

	legacy := findProbe(t, probes, probeIdLegacy)
	if !legacy.Succeeded || legacy.Version != tls.VersionTLS11 {
		t.Fatalf("legacy probe = %+v, want TLS 1.1", legacy)
	}
}

// Guards toolchain bumps: Go dropped 3DES from its defaults in 1.23, but the
// legacy probe still has to offer it when configured.
func TestRunMonitorProbes_TripleDesLegacyServer(t *testing.T) {
	serverCert, leaf := newSelfSignedRSACert(t, []net.IP{net.ParseIP("127.0.0.1")})

	probes := checkProbedMonitor(t, &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
	}, leaf)

	legacy := findProbe(t, probes, probeIdLegacy)
	if !legacy.Succeeded || legacy.CipherSuite != tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA {
		t.Fatalf("legacy probe = %+v, want TLS_RSA_WITH_3DES_EDE_CBC_SHA", legacy)
	}
}

func TestProbeResult_CapsTheError(t *testing.T) {
	result := probeResult(probeIdLegacy, nil, errors.New(strings.Repeat("e", 500)))

	if result.Succeeded {
		t.Fatal("expected a failed probe")
	}
	if len(result.Error) != probeErrorMaxLength {
		t.Fatalf("len(Error) = %d, want %d", len(result.Error), probeErrorMaxLength)
	}
	if result.Version != 0 || result.CipherSuite != 0 || result.CurveId != 0 {
		t.Fatalf("result = %+v, want no negotiated values on failure", result)
	}
}

func TestMonitorProbes_TableOrder(t *testing.T) {
	want := []string{probeIdX25519MLKEM768, probeIdSecP256r1MLKEM768, probeIdSecP384r1MLKEM1024, probeIdTls12, probeIdLegacy}
	if len(monitorProbes) != len(want) {
		t.Fatalf("len(monitorProbes) = %d, want %d", len(monitorProbes), len(want))
	}
	for i, id := range want {
		if monitorProbes[i].Id != id {
			t.Fatalf("monitorProbes[%d].Id = %q, want %q", i, monitorProbes[i].Id, id)
		}
	}
}
