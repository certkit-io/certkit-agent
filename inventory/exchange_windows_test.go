//go:build windows

package inventory

import (
	"testing"

	"github.com/certkit-io/certkit-agent/api"
)

func TestCanonicalizeExchangeServices(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "exact", in: "IIS,SMTP", want: "IIS,SMTP"},
		{name: "powershell spacing", in: "IIS, SMTP", want: "IIS,SMTP"},
		{name: "case and trim", in: " smtp , iis ", want: "SMTP,IIS"},
		{name: "drops unknown", in: "IIS,bogus,SMTP", want: "IIS,SMTP"},
		{name: "drops none", in: "None, SMTP", want: "SMTP"},
		{name: "all unknown", in: "nope,bad", want: ""},
		{name: "dedupes", in: "IIS,iis,IIS", want: "IIS"},
		{name: "extended services", in: "IMAP,POP,UM,UMCallRouter", want: "IMAP,POP,UM,UMCallRouter"},
		{name: "smtpclientauth", in: "SMTPClientAuth", want: "SMTPClientAuth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanonicalizeExchangeServices(tt.in); got != tt.want {
				t.Fatalf("CanonicalizeExchangeServices(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseExchangeCertificatesJSON(t *testing.T) {
	raw := `{ "value": [
		{ "Services": "IIS, SMTP", "Domains": "mail.contoso.com" },
		{ "Services": "IMAP, POP", "Domains": "imap.contoso.com" }
	], "Count": 2 }`

	certs := parseExchangeCertificatesJSON(raw)
	if len(certs) != 2 {
		t.Fatalf("expected 2 certs, got %d", len(certs))
	}
	if certs[0].Services != "IIS, SMTP" || certs[1].Services != "IMAP, POP" {
		t.Fatalf("unexpected certs: %+v", certs)
	}
}

func TestParseExchangeCertificatesJSONEmpty(t *testing.T) {
	for _, raw := range []string{"", "null", "   ", `{"value":[],"Count":0}`} {
		if certs := parseExchangeCertificatesJSON(raw); len(certs) != 0 {
			t.Fatalf("parseExchangeCertificatesJSON(%q) = %+v, want empty", raw, certs)
		}
	}
}

func TestExchangeInventoryItems(t *testing.T) {
	// One item per discovered certificate. Services drive the destination
	// (canonicalized, de-duped); wildcard domains normalize to their base and
	// non-FQDN tokens drop out. A certificate bound to no manageable service is
	// skipped entirely.
	certs := []exchangeCert{
		{Services: "IIS, SMTP, IMAP, SMTP", Domains: "mail.contoso.com,*.contoso.com,not a domain,mail.contoso.com"},
		{Services: "IMAP, POP", Domains: "imap.contoso.com"},
		{Services: "None", Domains: "ignored.contoso.com"},
	}

	items := exchangeInventoryItems(certs)
	if len(items) != 2 {
		t.Fatalf("expected 2 items (None-only cert skipped), got %d", len(items))
	}

	want := []api.InventoryItem{
		{
			Server:          "exchange",
			ConfigPath:      "Exchange",
			CertificatePath: "IIS,SMTP,IMAP",
			KeyPath:         "IIS,SMTP,IMAP",
			Domains:         "mail.contoso.com,contoso.com",
		},
		{
			Server:          "exchange",
			ConfigPath:      "Exchange",
			CertificatePath: "IMAP,POP",
			KeyPath:         "IMAP,POP",
			Domains:         "imap.contoso.com",
		},
	}
	for i, w := range want {
		if items[i] != w {
			t.Fatalf("item[%d]\n got = %+v\nwant = %+v", i, items[i], w)
		}
	}
}

func TestExchangeInventoryItemsEmpty(t *testing.T) {
	if items := exchangeInventoryItems(nil); len(items) != 0 {
		t.Fatalf("expected no items, got %+v", items)
	}
}
