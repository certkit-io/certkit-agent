package agent

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

func monitorRoots() *x509.CertPool {
	return freshSystemRoots()
}

// applyDomainMonitorUpdates applies the server's monitor list as the
// authoritative set: entries not present are dropped from config. LastChecked
// is cleared when the name or port changed so the edited monitor is re-checked
// on the next synchronization.
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
			PendingCheckNow: in.CheckRequestedDate,
		}

		prev, existed := previousByID[in.DomainId]
		if existed {
			entry.LastCheckNowHonored = prev.LastCheckNowHonored
			if prev.DomainName == in.DomainName && prev.Port == in.Port {
				entry.LastChecked = prev.LastChecked
			}
		}

		if !existed {
			log.Printf("Host monitor %s (%s:%d) added by server", in.DomainId, in.DomainName, in.Port)
			changed = true
		} else if prev.DomainName != in.DomainName ||
			prev.Port != in.Port ||
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

	serverName := monitor.DomainName
	if net.ParseIP(monitor.DomainName) != nil {
		// No SNI for IP targets, mirroring how the cloud prober behaves.
		serverName = ""
	}

	dialer := net.Dialer{Timeout: domainMonitorTimeout}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(monitor.DomainName, strconv.Itoa(monitor.Port)))
	if err != nil {
		result.FailureReason = failureUnableToRetrieveCertificate
		return result
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(domainMonitorTimeout)); err != nil {
		result.FailureReason = failureUnableToRetrieveCertificate
		return result
	}

	// InsecureSkipVerify captures the certificate even when it is invalid;
	// SAN coverage and chain trust are judged explicitly below.
	// VerifyPeerCertificate stashes the served chain the moment it arrives:
	// some endpoints (e.g. SIP-TLS gateways requiring mutual TLS) send their
	// certificate and then abort the handshake because we present no client
	// certificate. The chain is still worth reporting in that case.
	var peerCertificates []*x509.Certificate
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
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
	if err := tlsConn.Handshake(); err != nil && len(peerCertificates) == 0 {
		result.FailureReason = failureUnableToRetrieveCertificate
		return result
	}

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

	if err := leaf.VerifyHostname(monitor.DomainName); err != nil {
		result.FailureReason = failureCertificateDoesNotCoverDomain
		return result
	}

	intermediates := x509.NewCertPool()
	for _, cert := range peerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		result.FailureReason = failureX509ChainFailure
		flags := chainStatusFlags(err)
		result.ChainStatusFlags = &flags
		var unknownAuthorityErr x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthorityErr) {
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
