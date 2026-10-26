//go:build windows

package agent

import (
	"fmt"
	"strings"

	"github.com/certkit-io/certkit-agent/api"
	"github.com/certkit-io/certkit-agent/config"
	"github.com/certkit-io/certkit-agent/utils"
)

func synchronizeRemoteAccessCertificate(cfg config.CertificateConfiguration, change ConfigChange) api.AgentConfigStatusUpdate {
	return synchronizeWindowsServiceCert(cfg, change, windowsSyncConfig{
		serviceName: "RemoteAccess",
		applyFn: func(thumbprint string) (string, error) {
			return applyRemoteAccessSslCertificate(thumbprint, cfg.ConfigType)
		},
	})
}

func applyRemoteAccessSslCertificate(thumbprint string, configType string) (string, error) {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return "", fmt.Errorf("missing thumbprint for RemoteAccess binding")
	}

	isDirectAccess := strings.EqualFold(configType, "direct-access")

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
Import-Module RemoteAccess

$thumb = '%s'
$isDirectAccess = $%s
$serviceName = if ($isDirectAccess) { 'RaMgmtSvc' } else { 'RemoteAccess' }
$label = if ($isDirectAccess) { 'DirectAccess' } else { 'RRAS' }
Write-Host ($label + " Certificate Deployment  |  Service: " + $serviceName + "  |  Thumbprint: " + $thumb)

$certPath = "Cert:\LocalMachine\My\" + $thumb
$cert = Get-ChildItem $certPath -ErrorAction Stop

Write-Host "[Step 1] Setting Remote Access SSL certificate..."
Set-RemoteAccess -SslCertificate $cert -ErrorAction Stop

Write-Host ("[Step 2] Restarting " + $serviceName + " service...")
Restart-Service -Name $serviceName -Force -ErrorAction Stop

$deadline = (Get-Date).AddSeconds(120)
$lastState = ""
while ((Get-Date) -lt $deadline) {
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        throw ($serviceName + " service not found.")
    }

    $state = $svc.Status.ToString()
    if ($state -ne $lastState) {
        Write-Host ("  " + $serviceName + " service state: " + $state)
        $lastState = $state
    }

    if ($svc.Status -eq 'Running') {
        Write-Host ("DONE  |  " + $label + " SSL certificate updated to " + $thumb + ". " + $serviceName + " service is running.")
        return
    }

    if ($svc.Status -eq 'Stopped') {
        Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 2
}

throw ($serviceName + " service did not reach Running within timeout after applying certificate.")
`, escapePowerShellString(thumbprint), fmt.Sprintf("%t", isDirectAccess))

	out, err := utils.RunPowerShell(script)
	logPowerShellOutput("applyRemoteAccessSslCertificate", out)
	if err != nil {
		// RunPowerShell already wraps the output into err; returning out too
		// would duplicate it in the status message.
		return "", err
	}
	return out, nil
}
