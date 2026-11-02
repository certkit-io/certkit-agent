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

try {
    Set-RDCertificate -Role $role -Thumbprint $thumb -Force -ErrorAction Stop
} catch {
    # Set-RDCertificate assigns the certificate and then restarts the role's
    # service, giving up after 30 seconds. That limit is Microsoft's, and RD
    # Gateway often needs longer. So after any failure, settle the role's
    # service ourselves and check whether the certificate took before giving up.
    Write-Host "  Set-RDCertificate failed: $($_.Exception.Message.Trim())"

    $serviceName = if ($role -eq 'RDGateway') { 'TSGateway' } else { $null }
    $service = $null
    if ($serviceName) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    }
    if ($service -and $service.Status -like '*Pending') {
        Write-Host "  Waiting up to 5 minutes for service $serviceName to finish restarting"
        $deadline = (Get-Date).AddMinutes(5)
        while ($service.Status -like '*Pending' -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 5
            $service.Refresh()
        }
    }
    if ($service -and $service.Status -eq 'Stopped') {
        Write-Host "  Service $serviceName is stopped; starting it"
        Start-Service -Name $serviceName
        $service.Refresh()
    }
    if ($service -and $service.Status -ne 'Running') {
        Write-Host "  Service $serviceName is $($service.Status); giving up"
        throw
    }

    try {
        $applied = (Get-RDCertificate -Role $role -ErrorAction Stop).Thumbprint -replace '\s', ''
    } catch {
        Write-Host "  Could not read the certificate for role '$role': $($_.Exception.Message.Trim())"
        $applied = ''
    }
    if ($applied -ne $thumb) {
        Write-Host "  Role '$role' reports certificate '$applied' instead of '$thumb'; giving up"
        throw
    }
    if ($service) {
        Write-Host "  Service $serviceName is running and role '$role' reports the new certificate"
    } else {
        Write-Host "  Role '$role' reports the new certificate"
    }
}

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
