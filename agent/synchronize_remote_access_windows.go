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
			return "", applyRemoteAccessSslCertificate(thumbprint, cfg.ConfigType)
		},
	})
}

func applyRemoteAccessSslCertificate(thumbprint string, configType string) error {
	thumbprint = normalizeThumbprint(thumbprint)
	if thumbprint == "" {
		return fmt.Errorf("missing thumbprint for RemoteAccess binding")
	}

	isDirectAccess := strings.EqualFold(configType, "direct-access")

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
Import-Module RemoteAccess

$thumb = '%s'
$isDirectAccess = $%s
$serviceName = if ($isDirectAccess) { 'RaMgmtSvc' } else { 'RemoteAccess' }
$certPath = "Cert:\LocalMachine\My\" + $thumb
$cert = Get-ChildItem $certPath -ErrorAction Stop

Set-RemoteAccess -SslCertificate $cert -ErrorAction Stop

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
        Write-Host ($serviceName + " service state: " + $state)
        $lastState = $state
    }

    if ($svc.Status -eq 'Running') {
        Write-Host ("RemoteAccess SSL certificate updated. Active service: " + $serviceName)
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
	return err
}
