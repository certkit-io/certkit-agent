module github.com/certkit-io/certkit-agent

go 1.26.10

// Go 1.25 stopped accepting SHA-1 signatures in TLS 1.2 handshakes (RFC 9155).
// Old appliances (iLO/iDRAC firmware, switches, printers) still sign with
// SHA-1, and monitoring them must keep working.
godebug tlssha1=1

require (
	golang.org/x/crypto v0.40.0
	golang.org/x/sys v0.40.0
)

require github.com/pavlo-v-chernykh/keystore-go/v4 v4.5.0
