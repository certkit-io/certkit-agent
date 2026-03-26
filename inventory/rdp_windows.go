//go:build windows

package inventory

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type RDPProvider struct{}

func (RDPProvider) Name() string {
	return "rdp"
}

func (RDPProvider) Collect() ([]api.InventoryItem, error) {
	var items []api.InventoryItem

	if tsItems, ok := collectTerminalServices(); ok {
		items = append(items, tsItems...)
	}

	if rdItems, ok := collectRDCertificates(); ok {
		items = append(items, rdItems...)
	}

	return items, nil
}

type tsResult struct {
	HasCert    bool   `json:"HasCert"`
	Thumbprint string `json:"Thumbprint"`
	Domain     string `json:"Domain"`
}

func collectTerminalServices() ([]api.InventoryItem, bool) {
	script := `
try {
    $ts = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -ErrorAction Stop |
        Select-Object -First 1

    if (-not $ts -or [string]::IsNullOrWhiteSpace($ts.SSLCertificateSHA1Hash)) {
        return
    }

    $domain = ''
    $thumbprint = ($ts.SSLCertificateSHA1Hash -replace '\s', '')
    try {
        $cert = Get-ChildItem ("Cert:\LocalMachine\My\" + $thumbprint) -ErrorAction Stop
        if ($cert.DnsNameList -and $cert.DnsNameList.Count -gt 0) {
            $domain = $cert.DnsNameList[0].Unicode
        } elseif ($cert.Subject) {
            if ($cert.Subject -match 'CN=([^,]+)') { $domain = $Matches[1].Trim() }
        }
    } catch {}

    [pscustomobject]@{
        HasCert    = $true
        Thumbprint = $thumbprint
        Domain     = $domain
    } | ConvertTo-Json
} catch {
    return
}
`
	out, err := utils.RunPowerShell(script)
	if err != nil {
		log.Printf("RDP Terminal Services inventory lookup failed: %v", err)
		return nil, false
	}

	raw := strings.TrimSpace(out)
	if raw == "" || raw == "null" {
		return nil, true
	}

	var result tsResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		log.Printf("RDP Terminal Services JSON parse failed: %v", err)
		return nil, false
	}

	if !result.HasCert {
		return nil, true
	}

	var domains []string
	if normalized, ok := normalizeDomain(result.Domain); ok {
		domains = append(domains, normalized)
	}

	item := api.InventoryItem{
		Server:          "rdp",
		ConfigPath:      "TerminalServices",
		CertificatePath: "TerminalServices",
		KeyPath:         "TerminalServices",
		Domains:         joinDomains(domains),
	}

	return []api.InventoryItem{item}, true
}

type rdCertResult struct {
	Role       string `json:"Role"`
	Thumbprint string `json:"Thumbprint"`
	Domain     string `json:"Domain"`
}

type rdCertResultSet struct {
	Value []rdCertResult `json:"value"`
	Count int            `json:"Count"`
}

func collectRDCertificates() ([]api.InventoryItem, bool) {
	script := `
try {
    try { Import-Module RemoteDesktopServices -ErrorAction Stop } catch {}

    $certs = @(Get-RDCertificate -ErrorAction Stop)
    if ($certs.Count -eq 0) { return }

    $results = @()
    foreach ($c in $certs) {
        if ([string]::IsNullOrWhiteSpace($c.Thumbprint)) { continue }

        $domain = ''
        if ($c.Subject) {
            if ($c.Subject -match 'CN=([^,]+)') { $domain = $Matches[1].Trim() }
        }

        # Try to get SANs from the cert store
        if (-not $domain -or $domain -like '*…*') {
            try {
                $thumb = ($c.Thumbprint -replace '\s', '')
                $cert = Get-ChildItem ("Cert:\LocalMachine\My\" + $thumb) -ErrorAction Stop
                if ($cert.DnsNameList -and $cert.DnsNameList.Count -gt 0) {
                    $domain = $cert.DnsNameList[0].Unicode
                }
            } catch {}
        }

        $results += [pscustomobject]@{
            Role       = $c.Role.ToString()
            Thumbprint = ($c.Thumbprint -replace '\s', '')
            Domain     = $domain
        }
    }

    if ($results.Count -eq 0) { return }
    ,@($results) | ConvertTo-Json -Depth 5
} catch {
    return
}
`
	out, err := utils.RunPowerShell(script)

	if err != nil {
		log.Printf("RDP Get-RDCertificate inventory lookup failed: %v", err)
		return nil, false
	}

	raw := strings.TrimSpace(out)
	if raw == "" || raw == "null" {
		return nil, true
	}

	var result rdCertResultSet
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		log.Printf("RDP Get-RDCertificate JSON parse failed: %v", err)
		return nil, false
	}

	var items []api.InventoryItem
	for _, r := range result.Value {
		if strings.TrimSpace(r.Thumbprint) == "" {
			continue
		}

		var domains []string
		if normalized, ok := normalizeDomain(r.Domain); ok {
			domains = append(domains, normalized)
		}

		items = append(items, api.InventoryItem{
			Server:          "rdp",
			ConfigPath:      r.Role,
			CertificatePath: r.Role,
			KeyPath:         r.Role,
			Domains:         joinDomains(domains),
		})
	}

	return items, true
}
