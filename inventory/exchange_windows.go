//go:build windows

package inventory

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type ExchangeProvider struct{}

func (ExchangeProvider) Name() string {
	return "exchange"
}

func (ExchangeProvider) Collect() ([]api.InventoryItem, error) {
	certs, ok := loadExchangeCertificatesFromPowerShell()
	if !ok {
		return nil, nil
	}
	return exchangeInventoryItems(certs), nil
}

// exchangeInventoryItems emits one inventory item per discovered certificate. A
// given Exchange service (IIS, SMTP, IMAP, ...) can only ever bind one
// certificate, so service sets are disjoint across certs -- each item's service
// list is therefore a unique deploy target, and reporting per-cert (rather than a
// merged union) keeps each certificate's own domains intact.
func exchangeInventoryItems(certs []exchangeCert) []api.InventoryItem {
	items := make([]api.InventoryItem, 0, len(certs))
	for _, c := range certs {
		// The services the certificate actually serves become the deploy
		// destination, so the renewed certificate is re-enabled for the same set.
		services := CanonicalizeExchangeServices(c.Services)
		if services == "" {
			// Not bound to any service we can deploy to; nothing to manage.
			continue
		}

		domains := make([]string, 0)
		for _, token := range strings.Split(c.Domains, ",") {
			if normalized, ok := normalizeDomain(token); ok {
				domains = append(domains, normalized)
			}
		}

		items = append(items, api.InventoryItem{
			Server:          "exchange",
			ConfigPath:      "Exchange",
			CertificatePath: services,
			KeyPath:         services,
			Domains:         joinDomains(domains),
		})
	}
	return items
}

// DefaultExchangeServices matches the CertKit Exchange template default: enable a
// new certificate for IIS and SMTP. Used by the deploy side as the target when a
// stored destination yields no usable services list. Lives here (rather than in
// the agent package) because agent imports inventory, not the other way around.
const DefaultExchangeServices = "IIS,SMTP"

// knownExchangeServices maps lower-cased Exchange service tokens to their
// canonical Enable-ExchangeCertificate -Services spelling. This is the full set
// of services Exchange can bind a TLS certificate to. Anything outside it (and
// "None") is dropped, which keeps the canonicalized result safe to inject
// unquoted into the PowerShell -Services argument.
var knownExchangeServices = map[string]string{
	"federation":     "Federation",
	"imap":           "IMAP",
	"pop":            "POP",
	"um":             "UM",
	"umcallrouter":   "UMCallRouter",
	"iis":            "IIS",
	"smtp":           "SMTP",
	"smtpclientauth": "SMTPClientAuth",
}

// CanonicalizeExchangeServices parses a comma-separated services list — either
// the "IIS, SMTP" string Get-ExchangeCertificate emits during inventory or a
// stored deploy destination — into a canonical, de-duplicated, order-preserving
// comma-separated list. Unknown tokens and "None" are dropped. Returns "" when
// nothing usable remains; callers needing a deploy target fall back to
// DefaultExchangeServices.
func CanonicalizeExchangeServices(value string) string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 2)
	for _, token := range strings.Split(value, ",") {
		canonical, ok := knownExchangeServices[strings.ToLower(strings.TrimSpace(token))]
		if !ok {
			continue
		}
		if _, dup := seen[canonical]; dup {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	return strings.Join(out, ",")
}

// exchangeCert is one discovered Exchange certificate bound to at least one TLS
// service. Services and Domains are comma-separated strings rather than arrays:
// ConvertTo-Json unwraps a single-element array into a scalar, which would fail
// to decode into []string. Splitting a string in Go sidesteps that quirk.
type exchangeCert struct {
	Services string `json:"Services"`
	Domains  string `json:"Domains"`
}

type exchangeCertResultSet struct {
	Value []exchangeCert `json:"value"`
	Count int            `json:"Count"`
}

func loadExchangeCertificatesFromPowerShell() ([]exchangeCert, bool) {
	// Fast path first: the registered-snapin check is a cheap registry read, so
	// non-Exchange servers report "not found" without paying to load the (slow)
	// Exchange management runtime. Only registered boxes add the snap-in.
	//
	// Every discovery path emits a JSON array and exits 0 -- a missing snap-in or
	// absent Exchange is "not found", never an error.
	script := `
$snapin = Get-PSSnapin -Registered -Name Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue
if (-not $snapin) {
    ,@() | ConvertTo-Json
    exit 0
}

try {
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
} catch {
    ,@() | ConvertTo-Json
    exit 0
}

if (-not (Get-Command Get-ExchangeCertificate -ErrorAction SilentlyContinue)) {
    ,@() | ConvertTo-Json
    exit 0
}

$certs = @()
try {
    $certs = @(Get-ExchangeCertificate -ErrorAction Stop)
} catch {
    ,@() | ConvertTo-Json
    exit 0
}

# Report every certificate Exchange has bound to a TLS service (IIS, SMTP, IMAP,
# POP, UM, Federation, ...). Each service binds only one certificate, so the
# service sets are disjoint and each certificate is independently manageable.
$results = @()
foreach ($c in $certs) {
    $svc = [string]$c.Services
    if (-not $svc -or $svc -eq 'None') { continue }

    $domains = @()
    $thumb = ($c.Thumbprint -replace '\s', '')
    try {
        $cert = Get-ChildItem ("Cert:\LocalMachine\My\" + $thumb) -ErrorAction Stop
        if ($cert.DnsNameList -and $cert.DnsNameList.Count -gt 0) {
            foreach ($d in $cert.DnsNameList) {
                if (-not [string]::IsNullOrWhiteSpace($d.Unicode)) { $domains += $d.Unicode }
            }
        } elseif ($cert.Subject -match 'CN=([^,]+)') {
            $domains += $Matches[1].Trim()
        }
    } catch {}

    $results += [pscustomobject]@{
        Services = $svc
        Domains  = ($domains -join ',')
    }
}

,@($results) | ConvertTo-Json -Depth 5
exit 0
`

	out, err := utils.RunPowerShell(script)
	if err != nil {
		log.Printf("Exchange inventory lookup via PowerShell failed: %v", err)
		return nil, false
	}

	return parseExchangeCertificatesJSON(out), true
}

func parseExchangeCertificatesJSON(raw string) []exchangeCert {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil
	}

	var result exchangeCertResultSet
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		log.Printf("Exchange certificates JSON parse failed: %v", err)
	}
	return result.Value
}
