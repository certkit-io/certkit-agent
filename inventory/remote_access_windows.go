//go:build windows

package inventory

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type RemoteAccessProvider struct{}

func (RemoteAccessProvider) Name() string {
	return "remote-access"
}

func (RemoteAccessProvider) Collect() ([]api.InventoryItem, error) {
	result, ok := loadRemoteAccessInventoryFromPowerShell()
	if !ok {
		return nil, nil
	}

	domains := make([]string, 0, len(result.Domains))
	for _, domain := range result.Domains {
		if normalized, ok := normalizeDomain(domain); ok {
			domains = append(domains, normalized)
		}
	}

	var item api.InventoryItem
	if result.DAInstalled {
		item = api.InventoryItem{
			Server:          "direct-access",
			ConfigPath:      "DirectAccess",
			CertificatePath: "Direct Access",
			KeyPath:         "Direct Access",
			Domains:         joinDomains(domains),
		}
	} else {
		item = api.InventoryItem{
			Server:          "rras",
			ConfigPath:      "RRAS:SSTP",
			CertificatePath: "Routing and Remote Access:443",
			KeyPath:         "Routing and Remote Access:443",
			Domains:         joinDomains(domains),
		}
	}

	return []api.InventoryItem{item}, nil
}

type remoteAccessInventoryResult struct {
	DAInstalled bool     `json:"DAInstalled"`
	Domains     []string `json:"Domains"`
}

func loadRemoteAccessInventoryFromPowerShell() (remoteAccessInventoryResult, bool) {
	script := `
$domains = @()
$daInstalled = $false
try {
    $remoteAccess = Get-RemoteAccess -ErrorAction Stop
} catch {
    return
}

if ($remoteAccess.DAStatus -eq 'Installed') {
    $daInstalled = $true
}

if ($remoteAccess -and $remoteAccess.SslCertificate -and $remoteAccess.SslCertificate.Thumbprint) {
    $thumbprint = ($remoteAccess.SslCertificate.Thumbprint -replace '\s', '')
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
    DAInstalled = $daInstalled
    Domains     = $domains
} | ConvertTo-Json -Depth 5
`

	out, err := utils.RunPowerShell(script)
	if err != nil {
		log.Printf("RemoteAccess inventory lookup via PowerShell failed: %v", err)
		return remoteAccessInventoryResult{}, false
	}

	log.Print(out)

	raw := strings.TrimSpace(out)
	if raw == "" || raw == "null" {
		return remoteAccessInventoryResult{}, true
	}

	var result remoteAccessInventoryResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		log.Printf("RemoteAccess inventory JSON parse failed: %v", err)
		return remoteAccessInventoryResult{}, false
	}

	return result, true
}
