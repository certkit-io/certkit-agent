//go:build windows

package inventory

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/utils"
)

type IISProvider struct{}

func (IISProvider) Name() string {
	return "iis"
}

func (IISProvider) Collect() ([]api.InventoryItem, error) {
	bindings, ok := loadIISBindingsFromPowerShell()
	if !ok || len(bindings) == 0 {
		return nil, nil
	}
	return iisInventoryItems(bindings), nil
}

func iisInventoryItems(bindings []iisBinding) []api.InventoryItem {
	items := make([]api.InventoryItem, 0, len(bindings))
	for _, binding := range bindings {
		host := strings.TrimSpace(binding.Host)

		domains := make([]string, 0, 1)
		if value, ok := normalizeDomain(host); ok {
			domains = append(domains, value)
		}

		// For SNI bindings the destination is site:port:host so the deploy side can
		// target the exact binding. That three-part shape is the agent's only SNI
		// signal, since config_path and domains are not sent back from the CertKit
		// app. Non-SNI bindings stay site:port even when they carry a host header.
		destination := fmt.Sprintf("%s:%s", binding.Site, binding.Port)
		if binding.SslFlags&iisSslFlagSNI != 0 && host != "" {
			destination = fmt.Sprintf("%s:%s:%s", binding.Site, binding.Port, host)
		}

		items = append(items, api.InventoryItem{
			Server:          "iis",
			ConfigPath:      fmt.Sprintf("IIS:\\Sites|SslFlags=%d", binding.SslFlags),
			CertificatePath: destination,
			KeyPath:         destination,
			Domains:         joinDomains(domains),
		})
	}

	return items
}

// IIS sslFlags bit (0x1) marking a binding as SNI-enabled.
const iisSslFlagSNI = 1

type iisBinding struct {
	Site     string `json:"Site"`
	Port     string `json:"Port"`
	Host     string `json:"Host"`
	SslFlags int    `json:"SslFlags"`
}

type iisBindingResult struct {
	Value []iisBinding `json:"value"`
	Count int          `json:"Count"`
}

func loadIISBindingsFromPowerShell() ([]iisBinding, bool) {
	script := `

if (-not (Get-Module -ListAvailable -Name WebAdministration)) {
	,@() | ConvertTo-Json
	return
}

Import-Module WebAdministration

,@(
    Get-ChildItem IIS:\Sites |
    ForEach-Object {
        $site = $_

        foreach ($binding in $site.Bindings.Collection) {
            if ($binding.protocol -eq 'https') {
                $parts = $binding.bindingInformation -split ':', 3

                # Skip bindings without a numeric TCP port. Exchange and other
                # apps register https bindings whose bindingInformation does not
                # follow the IP:Port:Host shape, leaving a non-numeric value in
                # $parts[1] (e.g. "Default Web Site:f6b7").
                if ($parts[1] -notmatch '^\d+$') { continue }

                [pscustomobject]@{
                    Site     = $site.Name
                    Port     = $parts[1]
                    Host     = $parts[2]
                    SslFlags = [int]$binding.sslFlags
                }
            }
        }
    } |
    Select-Object -First 500
) | ConvertTo-Json
`
	out, err := utils.RunPowerShell(script)
	if err != nil {
		log.Printf("IIS SSL bindings lookup via PowerShell failed: %v", err)
		return nil, false
	}

	return parseIISBindingsJSON(out), true
}

// parseIISBindingsJSON decodes the {"value":[...],"Count":N} payload produced by
// the inventory PowerShell. A decode failure is logged and yields no bindings
// rather than failing the whole inventory run.
func parseIISBindingsJSON(raw string) []iisBinding {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "null" {
		return nil
	}

	var result iisBindingResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		log.Printf("IIS SSL bindings JSON parse failed: %v", err)
	}
	return result.Value
}
