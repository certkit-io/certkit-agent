//go:build linux

package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
)

// The same sources Go's crypto/x509 loadSystemRoots reads on Linux, so a
// fresh load sees exactly what a freshly started process would.
var systemCertFiles = []string{
	"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
	"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
	"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
	"/etc/pki/tls/cacert.pem",                           // OpenELEC
	"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
	"/etc/ssl/cert.pem",                                 // Alpine Linux
}

var systemCertDirectories = []string{
	"/etc/ssl/certs",     // SLES10/SLES11
	"/etc/pki/tls/certs", // Fedora/RHEL
}

// freshSystemRoots reads the OS trust store from disk. Go caches the
// process's system pool the first time it is used, so without this a private
// CA root installed by the trust feature after startup would stay untrusted
// until the agent restarts. Returns nil when nothing could be read so the
// caller falls back to Go's cached pool instead of an empty one (which would
// fail every chain).
func freshSystemRoots() *x509.CertPool {
	pool := x509.NewCertPool()
	loaded := false

	files := systemCertFiles
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		files = []string{f}
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		if pool.AppendCertsFromPEM(data) {
			loaded = true
		}
		// Like Go's loadSystemRoots: stop after the first readable file.
		break
	}

	dirs := systemCertDirectories
	if d := os.Getenv("SSL_CERT_DIR"); d != "" {
		dirs = strings.Split(d, ":")
	}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(dir + "/" + entry.Name())
			if err != nil {
				continue
			}
			// The pool de-duplicates by content, so bundle/symlink overlap
			// within these directories is harmless.
			if appendCACertsFromPEM(pool, data) {
				loaded = true
			}
		}
	}

	if !loaded {
		return nil
	}
	return pool
}

// appendCACertsFromPEM is AppendCertsFromPEM minus CA-issued leaf
// certificates. /etc/pki/tls/certs is also where RHEL keeps server
// certificates (nginx, Apache), and a leaf in the root pool makes Verify
// return just [leaf] without building the chain to the private CA root.
// Self-signed certificates are kept: they can only anchor themselves.
func appendCACertsFromPEM(pool *x509.CertPool, data []byte) bool {
	added := false
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return added
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		selfSigned := bytes.Equal(cert.RawSubject, cert.RawIssuer)
		if !cert.IsCA && !selfSigned {
			continue
		}
		pool.AddCert(cert)
		added = true
	}
}
