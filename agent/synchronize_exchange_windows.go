//go:build windows

package agent

import (
	"fmt"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/inventory"
	"github.com/certkit-io/certkit-agent/utils"
)

func synchronizeExchangeCertificate(cfg config.CertificateConfiguration, change ConfigChange) api.AgentConfigStatusUpdate {
	services := parseExchangeServices(cfg.PemDestination)

	return synchronizeWindowsServiceCert(cfg, change, windowsSyncConfig{
		serviceName: "Exchange",
		applyFn: func(thumbprint string) (string, error) {
			return "", applyExchangeCertificate(thumbprint, services)
		},
	})
}

// parseExchangeServices canonicalizes the deploy destination into a safe,
// comma-separated Exchange services list for Enable-ExchangeCertificate, falling
// back to the IIS,SMTP template default when the destination carries nothing
// usable. inventory.CanonicalizeExchangeServices restricts the result to known
// service tokens, keeping it safe to inject unquoted into -Services.
func parseExchangeServices(value string) string {
	if services := inventory.CanonicalizeExchangeServices(value); services != "" {
		return services
	}
	return inventory.DefaultExchangeServices
}

func applyExchangeCertificate(thumbprint, services string) error {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for Exchange certificate")
	}

	script := buildExchangeScript(thumbprint, services)
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyExchangeCertificate", out)
	return err
}

func buildExchangeScript(thumbprint, services string) string {
	// services is restricted to canonical Exchange service tokens by
	// parseExchangeServices, so it is safe to inject unquoted.
	return fmt.Sprintf(`
$ErrorActionPreference = 'Stop'

if (-not (Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue)) {
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
}

$thumb = '%s'
$certPath = "Cert:\LocalMachine\My\" + $thumb
if (-not (Test-Path $certPath)) {
    throw "Certificate $thumb not found in LocalMachine\My store."
}

Enable-ExchangeCertificate -Thumbprint $thumb -Services %s -Force

Write-Host "Exchange certificate $thumb enabled for services %s."
`, escapePowerShellString(thumbprint), services, services)
}
