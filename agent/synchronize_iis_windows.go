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
	siteName, port, host, err := parseIISDestination(cfg.PemDestination)
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
			return "", applyIISBinding(siteName, port, host, thumbprint)
		},
	})
}

func parseIISDestination(value string) (site string, port string, host string, err error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", "", fmt.Errorf("Error: missing IIS destination (expected site:port)")
	}
	// site:port, or site:port:host for SNI bindings.
	parts := strings.SplitN(value, ":", 3)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("Error: invalid IIS destination %q (expected site:port)", value)
	}
	site = strings.TrimSpace(parts[0])
	port = strings.TrimSpace(parts[1])
	if len(parts) == 3 {
		host = strings.TrimSpace(parts[2])
	}
	if site == "" || port == "" {
		return "", "", "", fmt.Errorf("Error: invalid IIS destination %q (expected site:port)", value)
	}
	return site, port, host, nil
}

func applyIISBinding(siteName, port, host, thumbprint string) error {
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for IIS binding")
	}
	script := buildIISBindingScript(siteName, port, host, thumbprint)
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyIISBinding", out)
	return err
}

func buildIISBindingScript(siteName, port, host, thumbprint string) string {
	// A non-empty host means the destination is three-part (site:port:host), which
	// the inventory only produces for SNI bindings.
	// SNI bindings share an IP:port and differ only by host header, so the
	// lookup must include the host to land on the right binding.
	useSNI := host != ""
	bindingLookup := "Get-WebBinding -Name $site -Protocol https -Port $port"
	bindingDesc := "site '$site' on port $port"
	if useSNI {
		bindingLookup += " -HostHeader $bindingHost"
		bindingDesc += " for host '$bindingHost'"
	}

	return fmt.Sprintf(`
Import-Module WebAdministration

$site        = '%s'
$port        = '%s'
$bindingHost = '%s'
$newThumb    = '%s'

$bindings = %s
if (-not $bindings) { throw "No HTTPS bindings found for %s." }

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
`, escapePowerShellString(siteName), escapePowerShellString(port), escapePowerShellString(host), escapePowerShellString(thumbprint), bindingLookup, bindingDesc)
}
