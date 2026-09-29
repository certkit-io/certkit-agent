package agent

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"
)

// A scripted plaintext exchange: the server sends greeting, then answers each
// line the client sends with the next reply. The last reply answers the
// STARTTLS command itself; refusal replaces it in the refused cases.
type fakeStartTLSExchange struct {
	name     string
	port     int
	greeting string
	replies  []string
	refusal  string
}

var fakeStartTLSExchanges = []fakeStartTLSExchange{
	{
		name:     "smtp",
		port:     587,
		greeting: "220-fake.local postscreen teaser\r\n220 fake.local ESMTP\r\n",
		replies:  []string{"250-fake.local\r\n250 STARTTLS\r\n", "220 2.0.0 Ready to start TLS\r\n"},
		refusal:  "454 4.7.0 TLS not available due to local problem\r\n",
	},
	{
		name:     "imap",
		port:     143,
		greeting: "* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready.\r\n",
		replies:  []string{"* untagged line before the reply\r\na1 OK Begin TLS negotiation now.\r\n"},
		refusal:  "a1 BAD Unknown command.\r\n",
	},
	{
		name:     "pop3",
		port:     110,
		greeting: "+OK Dovecot ready.\r\n",
		replies:  []string{"+OK Begin TLS negotiation now.\r\n"},
		refusal:  "-ERR Unknown command.\r\n",
	},
	{
		name:     "ftp",
		port:     21,
		greeting: "220-FileZilla Server 1.8.0\r\nfree-form banner line\r\n220 Please visit https://filezilla-project.org/\r\n",
		replies:  []string{"234 Using authentication type TLS.\r\n"},
		refusal:  "502 Command not implemented.\r\n",
	},
}

// startFakeStartTLSServer accepts one connection, plays greeting and replies,
// then serves cert over TLS.
func startFakeStartTLSServer(t *testing.T, cert tls.Certificate, greeting string, replies []string) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		conn.Write([]byte(greeting))
		for _, reply := range replies {
			reader.ReadString('\n')
			conn.Write([]byte(reply))
		}
		_ = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
	}()

	return listener.Addr().String()
}

func dialFakeStartTLSServer(t *testing.T, address string) net.Conn {
	t.Helper()

	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return conn
}

func TestNegotiateStartTLS_LeavesConnReadyForTLS(t *testing.T) {
	serverCert, leaf := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	for _, exchange := range fakeStartTLSExchanges {
		t.Run(exchange.name, func(t *testing.T) {
			conn := dialFakeStartTLSServer(t, startFakeStartTLSServer(t, serverCert, exchange.greeting, exchange.replies))

			if err := negotiateStartTLS(conn, exchange.port); err != nil {
				t.Fatalf("negotiateStartTLS: %v", err)
			}

			tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
			if err := tlsConn.Handshake(); err != nil {
				t.Fatalf("TLS handshake after negotiation: %v", err)
			}
			if !tlsConn.ConnectionState().PeerCertificates[0].Equal(leaf) {
				t.Fatal("expected the fake server's certificate after negotiation")
			}
		})
	}
}

func TestNegotiateStartTLS_Refused(t *testing.T) {
	serverCert, _ := newSelfSignedCert(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	for _, exchange := range fakeStartTLSExchanges {
		t.Run(exchange.name, func(t *testing.T) {
			replies := append([]string{}, exchange.replies[:len(exchange.replies)-1]...)
			replies = append(replies, exchange.refusal)
			conn := dialFakeStartTLSServer(t, startFakeStartTLSServer(t, serverCert, exchange.greeting, replies))

			err := negotiateStartTLS(conn, exchange.port)
			refusal := strings.TrimSpace(exchange.refusal)
			if err == nil || !strings.Contains(err.Error(), refusal) {
				t.Fatalf("negotiateStartTLS error = %v, want it to quote %q", err, refusal)
			}
		})
	}
}

func TestIsStartTLSPort(t *testing.T) {
	for port, want := range map[int]bool{21: true, 25: true, 110: true, 143: true, 587: true, 465: false, 993: false, 995: false, 443: false} {
		if got := isStartTLSPort(port); got != want {
			t.Errorf("isStartTLSPort(%d) = %t, want %t", port, got, want)
		}
	}
}
