package agent

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
)

const (
	domainMonitorRecheckInterval = 8 * time.Hour
	domainMonitorTimeout         = 2500 * time.Millisecond
)

// Defensive caps on the reported chain; a healthy chain is 2-4 certificates,
// a few KB. Anything past these is not worth shipping.
const (
	chainPemMaxCerts = 10
	chainPemMaxBytes = 256 * 1024
)

// Failure reasons match the server's DomainStatusReason enum member names verbatim.
const (
	failureUnableToRetrieveCertificate   = "UnableToRetrieveCertificate"
	failureCertificateDoesNotCoverDomain = "CertificateDoesNotCoverDomain"
	failureX509ChainFailure              = "X509ChainFailure"
)

// .NET X509ChainStatusFlags values the server renders into human-readable text.
const (
	chainFlagNotTimeValid     = 1
	chainFlagNotValidForUsage = 16
	chainFlagUntrustedRoot    = 32
	chainFlagPartialChain     = 65536
)

const rdpPort = 3389

// Microsoft's Remote Desktop Authentication EKU.
var oidRemoteDesktopAuthentication = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 54, 1, 2}

func monitorRoots() *x509.CertPool {
	return freshSystemRoots()
}

// applyDomainMonitorUpdates applies the server's monitor list as the
// authoritative set: entries not present are dropped from config. LastChecked
// is cleared when the name, port or host name override changed so the edited
// monitor is re-checked on the next synchronization.
func applyDomainMonitorUpdates(incoming []api.PollResponseDomainMonitor) {
	previous := config.CurrentConfig.DomainMonitors

	previousByID := make(map[string]config.DomainMonitorConfig, len(previous))
	for _, monitor := range previous {
		if monitor.DomainId != "" {
			previousByID[monitor.DomainId] = monitor
		}
	}

	updated := make([]config.DomainMonitorConfig, 0, len(incoming))
	changed := false
	for _, in := range incoming {
		if in.DomainId == "" {
			continue
		}

		entry := config.DomainMonitorConfig{
			DomainId:        in.DomainId,
			DomainName:      in.DomainName,
			Port:            in.Port,
			SniHostName:     in.SniHostName,
			PendingCheckNow: in.CheckRequestedDate,
		}

		prev, existed := previousByID[in.DomainId]
		if existed {
			entry.LastCheckNowHonored = prev.LastCheckNowHonored
			if prev.DomainName == in.DomainName && prev.Port == in.Port && prev.SniHostName == in.SniHostName {
				entry.LastChecked = prev.LastChecked
			}
		}

		if !existed {
			log.Printf("Host monitor %s (%s:%d) added by server", in.DomainId, in.DomainName, in.Port)
			changed = true
		} else if prev.DomainName != in.DomainName ||
			prev.Port != in.Port ||
			prev.SniHostName != in.SniHostName ||
			prev.PendingCheckNow != in.CheckRequestedDate {
			changed = true
		}

		updated = append(updated, entry)
	}

	for _, prev := range previous {
		stillMonitored := false
		for _, monitor := range updated {
			if monitor.DomainId == prev.DomainId {
				stillMonitored = true
				break
			}
		}
		if !stillMonitored {
			log.Printf("Host monitor %s (%s:%d) no longer assigned by server; removing from config", prev.DomainId, prev.DomainName, prev.Port)
			changed = true
		}
	}

	if !changed {
		return
	}

	config.CurrentConfig.DomainMonitors = updated
	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		log.Printf("Error saving config after host monitor update: %v", err)
	}
}

func SynchronizeDomainMonitors() []api.DomainMonitoringResultUpdate {
	results := make([]api.DomainMonitoringResultUpdate, 0, len(config.CurrentConfig.DomainMonitors))
	now := time.Now().UTC()

	var roots *x509.CertPool
	rootsLoaded := false

	for _, monitor := range config.CurrentConfig.DomainMonitors {
		if !shouldCheckMonitor(monitor, now) {
			continue
		}
		if checkNowPending(monitor) {
			log.Printf("Check now requested for host monitor %s (%s:%d); performing monitoring check", monitor.DomainId, monitor.DomainName, monitor.Port)
		}
		if !rootsLoaded {
			roots = monitorRoots()
			rootsLoaded = true
		}
		results = append(results, checkDomainMonitor(monitor, roots))
	}

	return results
}

// stampMonitorsChecked marks the reported monitors as checked. Called only
// after the results were uploaded successfully so a failed upload retries the
// whole check on the next poll cycle instead of silently losing the sample.
func stampMonitorsChecked(results []api.DomainMonitoringResultUpdate) {
	now := time.Now().UTC()
	for _, result := range results {
		for i := range config.CurrentConfig.DomainMonitors {
			monitor := &config.CurrentConfig.DomainMonitors[i]
			if monitor.DomainId != result.DomainId {
				continue
			}
			checkedAt := now
			monitor.LastChecked = &checkedAt
			if monitor.PendingCheckNow != "" {
				monitor.LastCheckNowHonored = monitor.PendingCheckNow
			}
			break
		}
	}

	if err := config.SaveConfig(&config.CurrentConfig, config.CurrentPath); err != nil {
		log.Printf("Error saving config after monitoring results upload: %v", err)
	}
}

// checkNowPending reports whether the server has an explicit check-now request
// the agent has not honored yet.
func checkNowPending(monitor config.DomainMonitorConfig) bool {
	return monitor.PendingCheckNow != "" && monitor.PendingCheckNow != monitor.LastCheckNowHonored
}

func shouldCheckMonitor(monitor config.DomainMonitorConfig, now time.Time) bool {
	if monitor.LastChecked == nil {
		return true
	}
	if checkNowPending(monitor) {
		return true
	}
	return now.Sub(*monitor.LastChecked) >= domainMonitorRecheckInterval
}

func checkDomainMonitor(monitor config.DomainMonitorConfig, roots *x509.CertPool) api.DomainMonitoringResultUpdate {
	result := api.DomainMonitoringResultUpdate{
		DomainId:  monitor.DomainId,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// The name the certificate must cover, and the one sent as SNI: the host
	// name override when the server picks its certificate by a different name
	// than the one dialed (an IP address, a load balancer's own name).
	certificateName := monitor.DomainName
	if monitor.SniHostName != "" {
		certificateName = monitor.SniHostName
	}

	serverName := certificateName
	if net.ParseIP(certificateName) != nil {
		// No SNI for IP targets, mirroring how the cloud prober behaves.
		serverName = ""
	}

	conn, err := dialMonitorTarget(monitor)
	if err != nil {
		result.FailureReason = failureUnableToRetrieveCertificate
		return result
	}

	// InsecureSkipVerify captures the certificate even when it is invalid;
	// SAN coverage and chain trust are judged explicitly below.
	// VerifyPeerCertificate stashes the served chain the moment it arrives:
	// some endpoints (e.g. SIP-TLS gateways requiring mutual TLS) send their
	// certificate and then abort the handshake because we present no client
	// certificate. The chain is still worth reporting in that case.
	// This handshake doubles as the browser-like "modern" probe, so the groups
	// it offers are pinned (monitorCurvePreferences).
	var peerCertificates []*x509.Certificate
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		CurvePreferences:   monitorCurvePreferences,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw)
				if err != nil {
					return err
				}
				certs = append(certs, cert)
			}
			peerCertificates = certs
			return nil
		},
	})
	handshakeErr := tlsConn.Handshake()
	modern := probeResult(probeIdModern, tlsConn, handshakeErr)
	remoteIP := remoteIPOf(conn)
	// The probes open their own connections.
	conn.Close()

	if len(peerCertificates) == 0 {
		result.FailureReason = failureUnableToRetrieveCertificate
		return result
	}

	leaf := peerCertificates[0]
	result.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	result.Expires = leaf.NotAfter.UTC().Format(time.RFC3339)
	result.Issuer = formatIssuerDN(leaf.Issuer)
	sha1Sum := sha1.Sum(leaf.Raw)
	result.Thumbprint = strings.ToUpper(hex.EncodeToString(sha1Sum[:]))
	sha256Sum := sha256.Sum256(leaf.Raw)
	result.Sha256 = strings.ToUpper(hex.EncodeToString(sha256Sum[:]))
	result.SerialNumber = formatSerialNumber(leaf.SerialNumber)
	result.ChainPem = encodeChainPem(peerCertificates)

	// Verified before the hostname check so the chain this host trusts is
	// reported even when the name doesn't match. The result fields are still
	// decided in the same order as before: hostname, then chain.
	intermediates := x509.NewCertPool()
	for _, cert := range peerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	verifyOptions := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     monitorKeyUsages(monitor.Port, leaf),
	}
	chains, verifyErr := leaf.Verify(verifyOptions)
	if verifyErr != nil {
		log.Printf("Host monitor %s (%s:%d, remote %s): certificate chain verification failed: %v", monitor.DomainId, monitor.DomainName, monitor.Port, remoteIP, verifyErr)
	}
	reportedChain := verifiedChainForReport(leaf, verifyOptions, chains, verifyErr)
	if verifyErr == nil {
		anchor := reportedChain[len(reportedChain)-1]
		log.Printf("Host monitor %s (%s:%d, remote %s): certificate chain verified; reporting %d certificates, trust anchor %q (SHA-256 %X)", monitor.DomainId, monitor.DomainName, monitor.Port, remoteIP, len(reportedChain), anchor.Subject.String(), sha256.Sum256(anchor.Raw))
	}

	result.Tls = &api.MonitorTlsDetails{
		RemoteIp:         remoteIP,
		VerifiedChainPem: encodeChainPem(reportedChain),
		Probes:           append([]api.MonitorTlsProbe{modern}, runMonitorProbes(monitor, serverName)...),
	}

	if err := leaf.VerifyHostname(certificateName); err != nil {
		result.FailureReason = failureCertificateDoesNotCoverDomain
		return result
	}

	if verifyErr != nil {
		result.FailureReason = failureX509ChainFailure
		flags := chainStatusFlags(verifyErr)
		result.ChainStatusFlags = &flags
		var unknownAuthorityErr x509.UnknownAuthorityError
		if errors.As(verifyErr, &unknownAuthorityErr) {
			rootInStore := false
			result.RootInTrustStore = &rootInStore
		}
		return result
	}

	rootInStore := true
	result.RootInTrustStore = &rootInStore
	result.Success = true
	return result
}

// dialMonitorTarget connects to the monitor's host and port and returns a
// connection ready for the TLS handshake: on mail and FTP ports the STARTTLS
// exchange has already run. The deadline covers the handshake too. The
// monitoring handshake and every probe connect through here.
func dialMonitorTarget(monitor config.DomainMonitorConfig) (net.Conn, error) {
	dialer := net.Dialer{Timeout: domainMonitorTimeout}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(monitor.DomainName, strconv.Itoa(monitor.Port)))
	if err != nil {
		return nil, err
	}

	timeout := domainMonitorTimeout
	if isStartTLSPort(monitor.Port) {
		timeout = startTLSMonitorTimeout
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	if isStartTLSPort(monitor.Port) {
		if err := negotiateStartTLS(conn, monitor.Port); err != nil {
			conn.Close()
			return nil, err
		}
	}

	return conn, nil
}

// remoteIPOf returns the address a connection reached, without the port.
func remoteIPOf(conn net.Conn) string {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	return ""
}

// verifiedChainForReport returns the chain this host's trust store verified,
// leaf first, or nil when nothing it trusts anchors the chain. The server
// rebuilds the chain from it and judges expiry and key usage itself, so when
// Verify failed only on those, it verifies again at a moment the leaf was
// valid and for any usage, purely to find the path to a trusted root. That
// second verification never changes the monitoring result.
func verifiedChainForReport(leaf *x509.Certificate, options x509.VerifyOptions, chains [][]*x509.Certificate, verifyErr error) []*x509.Certificate {
	if verifyErr == nil {
		return preferredVerifiedChain(chains)
	}

	var invalidErr x509.CertificateInvalidError
	if !errors.As(verifyErr, &invalidErr) {
		return nil
	}
	if invalidErr.Reason != x509.Expired && invalidErr.Reason != x509.IncompatibleUsage {
		return nil
	}

	options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	options.CurrentTime = leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)
	relaxedChains, err := leaf.Verify(options)
	if err != nil {
		return nil
	}
	return preferredVerifiedChain(relaxedChains)
}

// Go may return a chain ending at a trusted intermediate before one reaching
// a root. The server's CustomRootTrust verifier needs the latter when available.
// Only select among verified chains; never add an unverified issuer.
func preferredVerifiedChain(chains [][]*x509.Certificate) []*x509.Certificate {
	for _, chain := range chains {
		anchor := chain[len(chain)-1]
		if bytes.Equal(anchor.RawSubject, anchor.RawIssuer) {
			return chain
		}
	}
	return chains[0]
}

// monitorKeyUsages returns the usages the served certificate must be valid
// for. RDP clients accept the Remote Desktop Authentication EKU in place of
// serverAuth, and AD CS Remote Desktop templates issue it without serverAuth,
// so such a certificate on the RDP port is not held to serverAuth. Go cannot
// require an EKU it does not know, so usage checking is skipped for that case;
// trust, expiry and hostname are still checked.
func monitorKeyUsages(port int, leaf *x509.Certificate) []x509.ExtKeyUsage {
	serverAuth := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}

	if port != rdpPort {
		return serverAuth
	}

	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			return serverAuth
		}
	}

	for _, oid := range leaf.UnknownExtKeyUsage {
		if oid.Equal(oidRemoteDesktopAuthentication) {
			return []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		}
	}

	return serverAuth
}

// encodeChainPem renders the served chain, leaf first, as concatenated PEM
// blocks. Returns "" past the defensive caps.
func encodeChainPem(certs []*x509.Certificate) string {
	if len(certs) > chainPemMaxCerts {
		log.Printf("Not reporting certificate chain: %d certificates exceeds the cap of %d", len(certs), chainPemMaxCerts)
		return ""
	}

	var builder strings.Builder
	for _, cert := range certs {
		builder.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	}

	if builder.Len() > chainPemMaxBytes {
		log.Printf("Not reporting certificate chain: %d bytes exceeds the cap of %d", builder.Len(), chainPemMaxBytes)
		return ""
	}

	return builder.String()
}

// chainStatusFlags maps Go verification errors onto the .NET
// X509ChainStatusFlags values the server renders. Intentionally coarse: the
// value only feeds human-readable failure text.
func chainStatusFlags(err error) int {
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		switch invalidErr.Reason {
		case x509.Expired:
			return chainFlagNotTimeValid
		case x509.IncompatibleUsage:
			return chainFlagNotValidForUsage
		}
		return chainFlagPartialChain
	}

	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return chainFlagUntrustedRoot
	}

	return chainFlagPartialChain
}

// formatIssuerDN renders the issuer the way .NET's X500DistinguishedName does
// for typical certificates: most-specific attribute first, joined with ", ".
func formatIssuerDN(name pkix.Name) string {
	var parts []string
	if name.CommonName != "" {
		parts = append(parts, "CN="+name.CommonName)
	}
	for _, value := range name.OrganizationalUnit {
		if value != "" {
			parts = append(parts, "OU="+value)
		}
	}
	for _, value := range name.Organization {
		if value != "" {
			parts = append(parts, "O="+value)
		}
	}
	for _, value := range name.Locality {
		if value != "" {
			parts = append(parts, "L="+value)
		}
	}
	for _, value := range name.Province {
		if value != "" {
			parts = append(parts, "S="+value)
		}
	}
	for _, value := range name.Country {
		if value != "" {
			parts = append(parts, "C="+value)
		}
	}
	return strings.Join(parts, ", ")
}

// formatSerialNumber renders the serial the way .NET's X509Certificate2 does:
// uppercase hex, zero-padded to an even number of digits.
func formatSerialNumber(serial *big.Int) string {
	if serial == nil || serial.Sign() == 0 {
		return "00"
	}
	hexValue := strings.ToUpper(new(big.Int).Abs(serial).Text(16))
	if len(hexValue)%2 != 0 {
		hexValue = "0" + hexValue
	}
	return hexValue
}
