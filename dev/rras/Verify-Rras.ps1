param(
    [string]$CertFriendlyName = "CertKit RRAS Dev",
    [string]$VpnDnsName = "rras.dev.local"
)

$ErrorActionPreference = "Stop"

Write-Host "Checking RRAS service..."
Get-Service -Name RemoteAccess | Format-Table -AutoSize

Write-Host ""
Write-Host "Checking SSTP listener (TCP 443)..."
$listener = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    $listener | Select-Object LocalAddress, LocalPort, State | Format-Table -AutoSize
} else {
    Write-Host "No listener found on TCP 443."
}

Write-Host ""
Write-Host "Checking certificate in LocalMachine\\My..."
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.FriendlyName -eq $CertFriendlyName } |
    Select-Object -First 1
if ($cert) {
    $cert | Select-Object Subject, Thumbprint, NotAfter | Format-Table -AutoSize
} else {
    Write-Host "Certificate not found: $CertFriendlyName"
}

Write-Host ""
Write-Host "RRAS UI check:"
Write-Host "Open rrasmgmt.msc -> Server Properties -> Security tab."
Write-Host "Confirm the SSL certificate binding matches $VpnDnsName."
