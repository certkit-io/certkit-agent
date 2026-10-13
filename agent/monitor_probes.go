package agent

import (
	"crypto/tls"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

// After the monitoring handshake gets a certificate, the agent runs a few
// more handshakes, each offering a narrower set of options, to record which
// protocol versions and key exchanges the server accepts. The agent only
// reports what was negotiated; the server names and judges everything
// (PqcReadinessAnalyzer.AnalyzeObservation). These mirror the server's cloud
// probes (PqcReadinessAnalyzer.BuildProbes) minus what Go's TLS stack can't
// offer: pure ML-KEM and DHE suites. TLS 1.3 suites aren't configurable in Go;
// it offers the same three AEADs the cloud probes do.

// Probe ids, in the order they're reported. The server ignores ids it doesn't
// know, so a later agent can add probes.
const (
	probeIdModern             = "modern"
	probeIdX25519MLKEM768     = "x25519mlkem768"
	probeIdSecP256r1MLKEM768  = "secp256r1mlkem768"
	probeIdSecP384r1MLKEM1024 = "secp384r1mlkem1024"
	probeIdTls12              = "tls12"
	probeIdLegacy             = "legacy"
)

// probeErrorMaxLength caps each reported handshake error.
const probeErrorMaxLength = 200

// monitorCurvePreferences are the groups the monitoring handshake (the
// "modern" probe) offers: the cloud's "Modern browser" probe plus P-521,
// which monitoring offered before. Go sends key shares for X25519MLKEM768 and
// X25519, as the cloud probe does. Go ignores the order and filters its own
// default list, so pinning the list keeps a toolchain bump from changing what
// the handshake offers (Go 1.26's default adds SecP384r1MLKEM1024, which
// browsers don't offer).
var monitorCurvePreferences = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// monitorProbe is one deliberately narrow ClientHello.
type monitorProbe struct {
	Id           string
	MinVersion   uint16
	MaxVersion   uint16
	Curves       []tls.CurveID
	CipherSuites []uint16 // TLS 1.0-1.2 only; nil for the TLS 1.3-only probes
}

// The static RSA and 3DES suites aren't in Go's default list but are honored
// when configured. Go orders the suites itself, forward-secret AEADs first.
var monitorProbes = []monitorProbe{
	{
		Id:         probeIdX25519MLKEM768,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Curves:     []tls.CurveID{tls.X25519MLKEM768},
	},
	{
		Id:         probeIdSecP256r1MLKEM768,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Curves:     []tls.CurveID{tls.SecP256r1MLKEM768},
	},
	{
		Id:         probeIdSecP384r1MLKEM1024,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		Curves:     []tls.CurveID{tls.SecP384r1MLKEM1024},
	},
	{
		Id:         probeIdTls12,
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		Curves:     []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	},
	{
		Id:         probeIdLegacy,
		MinVersion: tls.VersionTLS10,
		MaxVersion: tls.VersionTLS11,
		Curves:     []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	},
}

// runMonitorProbes runs every probe in turn, each on its own connection with
// its own deadline.
func runMonitorProbes(monitor config.DomainMonitorConfig, serverName string) []api.MonitorTlsProbe {
	results := make([]api.MonitorTlsProbe, 0, len(monitorProbes))
	for _, probe := range monitorProbes {
		results = append(results, runMonitorProbe(monitor, serverName, probe))
	}
	return results
}

func runMonitorProbe(monitor config.DomainMonitorConfig, serverName string, probe monitorProbe) api.MonitorTlsProbe {
	conn, err := dialMonitorTarget(monitor)
	if err != nil {
		return probeResult(probe.Id, nil, err)
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         probe.MinVersion,
		MaxVersion:         probe.MaxVersion,
		CurvePreferences:   probe.Curves,
		CipherSuites:       probe.CipherSuites,
	})
	return probeResult(probe.Id, tlsConn, tlsConn.Handshake())
}

// probeResult records what a handshake negotiated, or why it failed. conn is
// only read when the handshake succeeded.
func probeResult(id string, conn *tls.Conn, handshakeErr error) api.MonitorTlsProbe {
	if handshakeErr != nil {
		message := handshakeErr.Error()
		if len(message) > probeErrorMaxLength {
			message = message[:probeErrorMaxLength]
		}
		return api.MonitorTlsProbe{Id: id, Error: message}
	}

	state := conn.ConnectionState()
	return api.MonitorTlsProbe{
		Id:          id,
		Succeeded:   true,
		Version:     state.Version,
		CipherSuite: state.CipherSuite,
		CurveId:     uint16(state.CurveID),
	}
}
