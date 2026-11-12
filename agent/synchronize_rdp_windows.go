//go:build windows

package agent

import (
	"fmt"
	"log"
	"os"
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
			return applyRDCertificate(cfg, thumbprint, role)
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

func applyRDCertificate(cfg config.CertificateConfiguration, thumbprint string, role string) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for RD certificate role %s", role)
	}

	// When this server holds every RD certificate role, Set-RDCertificate takes
	// the certificate from this server's store by thumbprint. Otherwise it is
	// given a PFX file, which the Connection Broker copies to every server
	// holding the role.
	pfxPath := ""
	pfxPassword := ""
	if !canSetRDCertificateByThumbprint() {
		pfx, err := api.FetchPfx(cfg.Id, cfg.CertificateId)
		if err != nil {
			return "", fmt.Errorf("fetching PFX: %w", err)
		}
		if pfx == nil || len(pfx.PfxBytes) == 0 {
			return "", fmt.Errorf("no issued PFX returned")
		}

		tempFile, err := os.CreateTemp("", "certkit-*.pfx")
		if err != nil {
			return "", fmt.Errorf("create temp pfx: %w", err)
		}
		pfxPath = tempFile.Name()
		defer os.Remove(pfxPath)

		if _, err := tempFile.Write(pfx.PfxBytes); err != nil {
			_ = tempFile.Close()
			return "", fmt.Errorf("write temp pfx: %w", err)
		}
		if err := tempFile.Close(); err != nil {
			return "", fmt.Errorf("close temp pfx: %w", err)
		}
		pfxPassword = pfx.Password
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'

Import-Module RemoteDesktop

$thumb = '%s'
$role = '%s'
$pfxPath = '%s'
$pfxPassword = '%s'
Write-Host "RDP Certificate Deployment  |  Role: $role  |  Thumbprint: $thumb"

try {
    if ($pfxPath) {
        Write-Host "  Importing the certificate from a PFX file"
        $securePassword = ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force
        Set-RDCertificate -Role $role -ImportPath $pfxPath -Password $securePassword -Force -ErrorAction Stop
    } else {
        Write-Host "  Using the certificate in this server's store"
        Set-RDCertificate -Role $role -Thumbprint $thumb -Force -ErrorAction Stop
    }
} catch {
    # Set-RDCertificate assigns the certificate and then restarts the role's
    # service, giving up after 30 seconds. That limit is Microsoft's, and RD
    # Gateway often needs longer. So after any failure, settle the role's
    # service ourselves before checking below whether the certificate took.
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
}

# Set-RDCertificate can print an error and still return normally, so the role
# only counts as updated once the deployment reports the new certificate for it.
try {
    $applied = (Get-RDCertificate -Role $role -ErrorAction Stop).Thumbprint -replace '\s', ''
} catch {
    Write-Host "  Could not read the certificate for role '$role': $($_.Exception.Message.Trim())"
    $applied = ''
}
if ($applied -ne $thumb) {
    Write-Host "  Role '$role' reports certificate '$applied' instead of '$thumb'; giving up"
    throw "RD certificate for role '$role' was not updated."
}

Write-Host "DONE  |  RD certificate for role '$role' updated to $thumb"
`, escapePowerShellString(thumbprint), escapePowerShellString(role), escapePowerShellString(pfxPath), escapePowerShellString(pfxPassword))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyRDCertificate", out)
	if err != nil {
		// RunPowerShell already wraps the output into err; returning out too
		// would duplicate it in the status message.
		return "", err
	}

	// When the role runs on this server, a PFX import puts the same certificate
	// into its store again. The friendly name is set again in case that import
	// replaced it, because cleanupOldCertKitCerts finds old certificates by it.
	if pfxPath != "" {
		if err := setCertFriendlyName(thumbprint, cfg.CertificateId); err != nil {
			log.Printf("Warning: failed to set certificate friendly name: %v", err)
		}
	}

	return out, nil
}

// canSetRDCertificateByThumbprint reports whether Set-RDCertificate can take
// the certificate from this server's store by thumbprint. That needs the
// -Thumbprint parameter (Windows Server 2019 or later) and a deployment whose
// Connection Broker, RD Web Access and RD Gateway roles are all on one server.
// That server is this one, because Get-RDServer asks this server as the
// deployment's Connection Broker. Session hosts do not hold these
// certificates. Anything unexpected counts as no, because the PFX import works
// in both cases.
func canSetRDCertificateByThumbprint() bool {
	script := `
$ErrorActionPreference = 'Stop'

Import-Module RemoteDesktop

$roleServers = @(Get-RDServer -ErrorAction Stop |
    Where-Object { "$($_.Roles)" -match 'RDS-(CONNECTION-BROKER|WEB-ACCESS|GATEWAY)' } |
    ForEach-Object { $_.Server } | Sort-Object -Unique)
$hasThumbprint = (Get-Command Set-RDCertificate).Parameters.ContainsKey('Thumbprint')
if ($hasThumbprint -and $roleServers.Count -eq 1) { 'thumbprint' } else { 'pfx' }
`
	out, err := utils.RunPowerShell(script)
	if err != nil {
		log.Printf("RDP: could not look up the servers in the RD deployment, so the certificate is imported from a PFX: %v", err)
		return false
	}
	return strings.TrimSpace(out) == "thumbprint"
}
