//go:build windows

package inventory

import (
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
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

	items := make([]api.InventoryItem, 0, len(bindings))
	for _, binding := range bindings {
		domains := make([]string, 0, 1)
		if value, ok := normalizeDomain(binding.Host); ok {
			domains = append(domains, value)
		}
		log.Printf("Binding: %v", binding)
		pemPath := fmt.Sprintf("%s:%d", binding.Site, binding.Port)

		items = append(items, api.InventoryItem{
			Server:          "iis",
			ConfigPath:      "IIS:\\SslBindings",
			CertificatePath: pemPath,
			KeyPath:         pemPath,
			Domains:         joinDomains(domains),
		})
	}

	return items, nil
}

type iisBinding struct {
	Site string `json:"Site"`
	Port int    `json:"Port"`
	Host string `json:"Host"`
}

type iisBindingResult struct {
	Value []iisBinding `json:"value"`
	Count int          `json:"Count"`
}

func loadIISBindingsFromPowerShell() ([]iisBinding, bool) {
	script := `
Import-Module WebAdministration

,@(
    Get-ChildItem IIS:\SslBindings |
    ForEach-Object {
        $port = $_.Port
        $hostName = $_.Host

        foreach ($s in $_.Sites) {
            [pscustomobject]@{
                Site = $s.Value
                Port = $port
                Host = $hostName
            }
        }
    } |
    Select-Object -First 10
) | ConvertTo-Json
`
	cmd := exec.Command(
		"powershell",
		"-NoProfile",
		"-Command",
		script,
	)
	out, err := cmd.Output()

	if err != nil {
		log.Printf("IIS SSL bindings lookup via PowerShell failed: %v", err)
		return nil, false
	}

	raw := strings.TrimSpace(string(out))

	log.Print(raw)
	if raw == "" || raw == "null" {
		return nil, true
	}

	var result iisBindingResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		log.Printf("IIS SSL bindings JSON parse failed: %v", err)
	}
	bindings := result.Value

	return bindings, true
}
