//go:build windows

package agent

import (
	"fmt"
	"strings"

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
			return applyExchangeCertificate(thumbprint, services)
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

// servicesIncludeSMTP reports whether the canonical comma-separated services
// list contains the exact SMTP token (SMTPClientAuth does not count). Connector
// TlsCertificateName updates only apply to SMTP transport deployments.
func servicesIncludeSMTP(services string) bool {
	for _, token := range strings.Split(services, ",") {
		if token == "SMTP" {
			return true
		}
	}
	return false
}

func applyExchangeCertificate(thumbprint, services string) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for Exchange certificate")
	}

	script := buildExchangeScript(thumbprint, services)
	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyExchangeCertificate", out)
	if err != nil {
		// RunPowerShell already wraps the output into err; returning out too
		// would duplicate it in the status message.
		return "", err
	}
	return strings.TrimSpace(out), nil
}

func buildExchangeScript(thumbprint, services string) string {
	// services is restricted to canonical Exchange service tokens by
	// parseExchangeServices, so it is safe to inject unquoted.
	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'

if (-not (Get-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue)) {
    Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
}

$thumb = '%s'
$certPath = "Cert:\LocalMachine\My\" + $thumb
if (-not (Test-Path $certPath)) {
    throw "Certificate $thumb not found in LocalMachine\My store."
}

$wantedServices = @('%s'.Split(','))
$currentServices = @(([string](Get-ExchangeCertificate -Thumbprint $thumb).Services).Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$missingServices = @($wantedServices | Where-Object { $currentServices -notcontains $_ })
if ($missingServices.Count -eq 0) {
    Write-Host "Exchange certificate $thumb already enabled for services $($wantedServices -join ',')."
} else {
    Enable-ExchangeCertificate -Thumbprint $thumb -Services %s -Force
    Write-Host "Exchange certificate $thumb enabled for services $($wantedServices -join ',')."
}
`, escapePowerShellString(thumbprint), services, services)

	if servicesIncludeSMTP(services) {
		script += exchangeConnectorScript
	}
	return script
}

// exchangeConnectorScript refreshes TlsCertificateName on Send/Receive
// connectors after the certificate is enabled for SMTP.
const exchangeConnectorScript = `
$cert = Get-ExchangeCertificate -Thumbprint $thumb
$newTls = "<I>$($cert.Issuer)<S>$($cert.Subject)"
# Comparison-only normalization; the value written is always the exact $newTls.
$newSubjectCmp = ($cert.Subject -replace ',\s+', ',').Trim()
$newTlsCmp = ($newTls -replace ',\s+', ',').Trim()

$updated = @()
$alreadyCurrent = 0
$otherCert = 0
$unparsed = @()
$failed = @()

$targets = @()
foreach ($rc in @(Get-ReceiveConnector -Server $env:COMPUTERNAME)) { $targets += ,@('Receive', $rc) }
foreach ($sc in @(Get-SendConnector)) { $targets += ,@('Send', $sc) }

foreach ($t in $targets) {
    $kind = $t[0]
    $conn = $t[1]
    # TlsCertificateName is an SmtpX509Identifier when read from Exchange; [string] yields "<I>...<S>...".
    $existing = ([string]$conn.TlsCertificateName).Trim()
    if (-not $existing) { continue }

    if ($existing -notmatch '(?i)^<I>(.*)<S>(.*)$') {
        $unparsed += "$kind '$($conn.Name)'"
        continue
    }
    $subjectCmp = ($Matches[2] -replace ',\s+', ',').Trim()

    if ($subjectCmp -ne $newSubjectCmp) { $otherCert++; continue }
    if (($existing -replace ',\s+', ',').Trim() -eq $newTlsCmp) { $alreadyCurrent++; continue }

    try {
        if ($kind -eq 'Receive') {
            Set-ReceiveConnector -Identity $conn.Identity -TlsCertificateName $newTls
        } else {
            Set-SendConnector -Identity $conn.Identity -TlsCertificateName $newTls
        }
        Write-Host "Updated $kind connector '$($conn.Name)' to $newTls"
        $updated += "$kind '$($conn.Name)'"
    } catch {
        $failed += "$kind '$($conn.Name)': $($_.Exception.Message)"
    }
}

if ($unparsed.Count -gt 0) {
    Write-Host "Left alone (unrecognized TlsCertificateName format): $($unparsed -join ', ')"
}
if ($failed.Count -gt 0) {
    throw "The certificate was enabled, but updating TlsCertificateName failed on: $($failed -join '; ')"
}
Write-Host "DONE  |  connectors: $($updated.Count) updated, $alreadyCurrent already current, $otherCert bound to a different certificate"
`
