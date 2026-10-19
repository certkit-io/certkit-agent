package agent

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// Mail and FTP servers on these ports greet in plaintext and only switch to
// TLS after a protocol-specific command (SMTP and IMAP STARTTLS, POP3 STLS,
// FTP AUTH TLS), so a TLS handshake sent right after connecting fails.
// checkDomainMonitor runs negotiateStartTLS first on these ports, matching the
// server's cloud checks (StartTls.cs).

// startTLSMonitorTimeout replaces domainMonitorTimeout once connected on these
// ports. Postfix's postscreen can hold the SMTP greeting back ~6 seconds on
// first contact and never allowlists a client that hangs up before then.
const startTLSMonitorTimeout = 15 * time.Second

// startTLSMaxNegotiationBytes only stops a misbehaving server from streaming
// forever before TLS starts; a real exchange is well under 1 KB.
const startTLSMaxNegotiationBytes = 64 * 1024

func isStartTLSPort(port int) bool {
	return port == 21 || port == 25 || port == 110 || port == 143 || port == 587
}

// negotiateStartTLS runs the plaintext exchange for port and returns once the
// server agrees, leaving conn ready for the TLS handshake. Servers send nothing
// after agreeing until the client speaks TLS, so the buffered reader can't hold
// back any handshake bytes.
func negotiateStartTLS(conn net.Conn, port int) error {
	reader := textproto.NewReader(bufio.NewReader(io.LimitReader(conn, startTLSMaxNegotiationBytes)))

	switch port {
	case 25, 587:
		return startSMTPTLS(conn, reader)
	case 143:
		return startIMAPTLS(conn, reader)
	case 110:
		return startPOP3TLS(conn, reader)
	case 21:
		return startFTPTLS(conn, reader)
	}
	return fmt.Errorf("port %d has no STARTTLS exchange", port)
}

func startSMTPTLS(conn net.Conn, reader *textproto.Reader) error {
	if _, _, err := reader.ReadResponse(220); err != nil {
		return fmt.Errorf("read SMTP greeting: %w", err)
	}

	if _, err := io.WriteString(conn, "EHLO certkit.io\r\n"); err != nil {
		return fmt.Errorf("send EHLO: %w", err)
	}
	if _, _, err := reader.ReadResponse(250); err != nil {
		return fmt.Errorf("read EHLO reply: %w", err)
	}

	if _, err := io.WriteString(conn, "STARTTLS\r\n"); err != nil {
		return fmt.Errorf("send STARTTLS: %w", err)
	}
	if _, _, err := reader.ReadResponse(220); err != nil {
		return fmt.Errorf("read STARTTLS reply: %w", err)
	}

	return nil
}

// The command is tagged "a1" so its reply can be told apart from any untagged
// "* ..." lines sent before it.
func startIMAPTLS(conn net.Conn, reader *textproto.Reader) error {
	greeting, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("read IMAP greeting: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(greeting), "* OK") {
		return fmt.Errorf("IMAP greeting was %q", greeting)
	}

	if _, err := io.WriteString(conn, "a1 STARTTLS\r\n"); err != nil {
		return fmt.Errorf("send STARTTLS: %w", err)
	}
	// Ends at the tagged reply, or at the reader's byte limit or conn's deadline.
	for {
		line, err := reader.ReadLine()
		if err != nil {
			return fmt.Errorf("read STARTTLS reply: %w", err)
		}
		if !strings.HasPrefix(strings.ToUpper(line), "A1 ") {
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(line), "A1 OK") {
			return fmt.Errorf("server answered STARTTLS with %q", line)
		}
		return nil
	}
}

func startPOP3TLS(conn net.Conn, reader *textproto.Reader) error {
	greeting, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("read POP3 greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return fmt.Errorf("POP3 greeting was %q", greeting)
	}

	if _, err := io.WriteString(conn, "STLS\r\n"); err != nil {
		return fmt.Errorf("send STLS: %w", err)
	}
	reply, err := reader.ReadLine()
	if err != nil {
		return fmt.Errorf("read STLS reply: %w", err)
	}
	if !strings.HasPrefix(reply, "+OK") {
		return fmt.Errorf("server answered STLS with %q", reply)
	}

	return nil
}

// ReadResponse also accepts FTP's multi-line form, where the lines between
// the first and the last don't have to start with the reply code.
func startFTPTLS(conn net.Conn, reader *textproto.Reader) error {
	if _, _, err := reader.ReadResponse(220); err != nil {
		return fmt.Errorf("read FTP greeting: %w", err)
	}

	if _, err := io.WriteString(conn, "AUTH TLS\r\n"); err != nil {
		return fmt.Errorf("send AUTH TLS: %w", err)
	}
	if _, _, err := reader.ReadResponse(234); err != nil {
		return fmt.Errorf("read AUTH TLS reply: %w", err)
	}

	return nil
}
