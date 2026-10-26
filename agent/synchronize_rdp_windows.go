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

func synchronizeRDPCertificate(cfg config.CertificateConfiguration, change ConfigChange) api.AgentConfigStatusUpdate {
	role := strings.TrimSpace(cfg.PemDestination)
	if role == "" {
		return api.AgentConfigStatusUpdate{
			ConfigId:       cfg.Id,
			LastStatusDate: time.Now().UTC(),
			Status:         statusErrorGeneral,
			Message:        "Error: missing RDP role in PemDestination",
		}
	}

	return synchronizeWindowsServiceCert(cfg, change, windowsSyncConfig{
		serviceName: fmt.Sprintf("RDP/%s", role),
		applyFn: func(thumbprint string) (string, error) {
			if strings.EqualFold(role, "TerminalServices") || strings.EqualFold(role, "Terminal Services") {
				return applyTerminalServicesCertificate(thumbprint)
			}
			return applyRDCertificate(thumbprint, role)
		},
	})
}

func applyTerminalServicesCertificate(thumbprint string) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for Terminal Services")
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'

$thumb = '%s'
Write-Host "RDP Certificate Deployment  |  Role: Terminal Services  |  Thumbprint: $thumb"

$certPath = "Cert:\LocalMachine\My\" + $thumb
if (-not (Test-Path $certPath)) {
    throw "Certificate $thumb not found in LocalMachine\My store."
}

$tsSettings = Get-CimInstance -Namespace root/cimv2/TerminalServices -ClassName Win32_TSGeneralSetting -ErrorAction Stop |
    Select-Object -First 1

if (-not $tsSettings) {
    throw "Unable to find Terminal Services general settings via CIM."
}

$currentThumb = ($tsSettings.SSLCertificateSHA1Hash -replace '\s', '').ToUpper()
if ($currentThumb -eq $thumb.ToUpper()) {
    Write-Host "DONE  |  Terminal Services already uses $thumb. No update needed."
    return
}

$previousThumb = if ($currentThumb) { $currentThumb } else { 'none' }
Write-Host "  Updating Terminal Services listener: $previousThumb -> $thumb"

$tsPath = $tsSettings | Get-CimInstance
Set-CimInstance -InputObject $tsPath -Property @{ SSLCertificateSHA1Hash = $thumb } -ErrorAction Stop

Write-Host "DONE  |  Terminal Services certificate updated to $thumb"
`, escapePowerShellString(thumbprint))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyTerminalServicesCertificate", out)
	if err != nil {
		// RunPowerShell already wraps the output into err; returning out too
		// would duplicate it in the status message.
		return "", err
	}
	return out, nil
}

func applyRDCertificate(thumbprint string, role string) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for RD certificate role %s", role)
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'

try { Import-Module RemoteDesktopServices -ErrorAction Stop } catch {}

$thumb = '%s'
$role = '%s'
Write-Host "RDP Certificate Deployment  |  Role: $role  |  Thumbprint: $thumb"

$certPath = "Cert:\LocalMachine\My\" + $thumb
if (-not (Test-Path $certPath)) {
    throw "Certificate $thumb not found in LocalMachine\My store."
}

Set-RDCertificate -Role $role -Thumbprint $thumb -Force -ErrorAction Stop

Write-Host "DONE  |  RD certificate for role '$role' updated to $thumb"
`, escapePowerShellString(thumbprint), escapePowerShellString(role))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyRDCertificate", out)
	if err != nil {
		// RunPowerShell already wraps the output into err; returning out too
		// would duplicate it in the status message.
		return "", err
	}
	return out, nil
}
