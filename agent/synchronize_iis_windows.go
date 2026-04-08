//go:build windows

package agent

import (
	"fmt"
	"strings"
	"time"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func synchronizeIISCertificate(cfg config.CertificateConfiguration, change ConfigChange) api.AgentConfigStatusUpdate {
	siteName, port, err := parseIISDestination(cfg.PemDestination)
	if err != nil {
		return api.AgentConfigStatusUpdate{
			ConfigId:       cfg.Id,
			LastStatusDate: time.Now().UTC(),
			Status:         statusErrorGeneral,
			Message:        err.Error(),
		}
	}

	return synchronizeWindowsServiceCert(cfg, change, windowsSyncConfig{
		serviceName: "IIS",
		applyFn: func(thumbprint string) (string, error) {
			return "", applyIISBinding(siteName, port, thumbprint)
		},
	})
}

func parseIISDestination(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", fmt.Errorf("Error: missing IIS destination (expected site:port)")
	}
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("Error: invalid IIS destination %q (expected site:port)", value)
	}
	site := strings.TrimSpace(parts[0])
	port := strings.TrimSpace(parts[1])
	if site == "" || port == "" {
		return "", "", fmt.Errorf("Error: invalid IIS destination %q (expected site:port)", value)
	}
	return site, port, nil
}

func applyIISBinding(siteName, port, thumbprint string) error {
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for IIS binding")
	}
	script := fmt.Sprintf(`
Import-Module WebAdministration

$site     = '%s'
$port     = '%s'
$newThumb = '%s'

$bindings = Get-WebBinding -Name $site -Protocol https -Port $port
if (-not $bindings) { throw "No HTTPS bindings found for site '$site' on port $port." }

foreach ($binding in @($bindings)) {
    # Resolve currently bound cert thumbprint (if any)
    $currentThumbprint = if ($binding.CertificateHash) {
        $p = "Cert:\LocalMachine\My\$(($binding.CertificateHash -join ''))"
        if (Test-Path $p) { (Get-Item $p).Thumbprint }
    }

    if ($currentThumbprint -eq $newThumb) {
        Write-Host "Certificate already current for $site ($($binding.bindingInformation)). No update needed."
        continue
    }

    Write-Host "Updating $site ($($binding.bindingInformation)) -> $newThumb..."

    $binding.AddSslCertificate($newThumb, "My")

}

Write-Host "IIS bindings updated."
`, escapePowerShellString(siteName), escapePowerShellString(port), escapePowerShellString(thumbprint))
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyIISBinding", out)
	return err
}
