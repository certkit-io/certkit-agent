//go:build windows

package inventory

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type RRASProvider struct{}

func (RRASProvider) Name() string {
	return "rras"
}

func (RRASProvider) Collect() ([]api.InventoryItem, error) {
	result, ok := loadRRASInventoryFromPowerShell()
	if !ok {
		return nil, nil
	}

	if !result.ServiceRunning || !result.Listening443 {
		return nil, nil
	}

	domains := make([]string, 0, len(result.Domains))
	for _, domain := range result.Domains {
		if normalized, ok := normalizeDomain(domain); ok {
			domains = append(domains, normalized)
		}
	}

	item := api.InventoryItem{
		Server:          "rras",
		ConfigPath:      "RRAS:SSTP",
		CertificatePath: "Routing and Remote Access:443",
		KeyPath:         "Routing and Remote Access:443",
		Domains:         joinDomains(domains),
	}

	return []api.InventoryItem{item}, nil
}

type rrasInventoryResult struct {
	ServiceRunning bool     `json:"ServiceRunning"`
	Listening443   bool     `json:"Listening443"`
	Thumbprint     string   `json:"Thumbprint"`
	Domains        []string `json:"Domains"`
}

func loadRRASInventoryFromPowerShell() (rrasInventoryResult, bool) {
	script := `
$service = Get-Service -Name RemoteAccess -ErrorAction SilentlyContinue
if (-not $service -or $service.Status -ne 'Running') {
    [pscustomobject]@{
        ServiceRunning = $false
        Listening443   = $false
        Thumbprint     = ""
        Domains        = @()
    } | ConvertTo-Json -Depth 5
    return
}

$listener = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $listener) {
    [pscustomobject]@{
        ServiceRunning = $true
        Listening443   = $false
        Thumbprint     = ""
        Domains        = @()
    } | ConvertTo-Json -Depth 5
    return
}

$thumbprint = ""
$domains = @()
try {
    $remoteAccess = Get-RemoteAccess -ErrorAction Stop
    if ($remoteAccess -and $remoteAccess.SslCertificate -and $remoteAccess.SslCertificate.Thumbprint) {
        $thumbprint = ($remoteAccess.SslCertificate.Thumbprint -replace '\s', '')
    }
} catch {
}

if ($thumbprint) {
    $cert = Get-ChildItem ("Cert:\LocalMachine\My\" + $thumbprint) -ErrorAction SilentlyContinue
    if ($cert -and $cert.DnsNameList) {
        $domains = @(
            $cert.DnsNameList |
            ForEach-Object { $_.Unicode } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }
}

[pscustomobject]@{
    ServiceRunning = $true
    Listening443   = $true
    Thumbprint     = $thumbprint
    Domains        = $domains
} | ConvertTo-Json -Depth 5
`

	out, err := utils.RunPowerShell(script)
	if err != nil {
		log.Printf("RRAS inventory lookup via PowerShell failed: %v", err)
		return rrasInventoryResult{}, false
	}

	raw := strings.TrimSpace(out)
	if raw == "" || raw == "null" {
		return rrasInventoryResult{}, true
	}

	var result rrasInventoryResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		log.Printf("RRAS inventory JSON parse failed: %v", err)
		return rrasInventoryResult{}, false
	}

	return result, true
}
