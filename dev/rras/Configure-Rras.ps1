param(
    [string]$VpnDnsName = "rras.dev.local",
    [string]$CertFriendlyName = "CertKit RRAS Dev",
    [string]$ExportCertPath = "C:\rras\certs\rras-dev.cer"
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "Run this script as Administrator."
}

$featureNames = @("RemoteAccess", "DirectAccess-VPN", "Routing")
$features = Get-WindowsFeature | Where-Object { $featureNames -contains $_.Name }
if (-not $features) {
    throw "Remote Access features not found. Are you on Windows Server?"
}

$toInstall = $features | Where-Object { -not $_.Installed } | Select-Object -ExpandProperty Name
if ($toInstall) {
    Install-WindowsFeature -Name $toInstall -IncludeManagementTools | Out-Null
}

$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.FriendlyName -eq $CertFriendlyName } |
    Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -DnsName $VpnDnsName `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -FriendlyName $CertFriendlyName
}

$certDir = Split-Path -Parent $ExportCertPath
New-Item -ItemType Directory -Force -Path $certDir | Out-Null
Export-Certificate -Cert $cert -FilePath $ExportCertPath -Force | Out-Null

$ruleName = "RRAS SSTP (TCP 443)"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow | Out-Null
}

Write-Host ""
Write-Host "RRAS role installed and self-signed certificate created."
Write-Host "Next: Configure RRAS via the wizard:"
Write-Host "1) Open 'Routing and Remote Access' (rrasmgmt.msc)."
Write-Host "2) Right-click the server -> Configure and Enable Routing and Remote Access."
Write-Host "3) Choose 'Custom configuration' and enable 'VPN access'."
Write-Host "4) Finish the wizard and start the service."
Write-Host ""
Write-Host "Certificate exported to: $ExportCertPath"
Write-Host "Hostname for SSTP: $VpnDnsName (add a hosts entry on your host)."
