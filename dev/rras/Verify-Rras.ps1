$service = Get-Service -Name RemoteAccess -ErrorAction SilentlyContinue
if (-not $service -or $service.Status -ne 'Running') {
    [pscustomobject]@{
        ServiceRunning = $false
        Listening443   = $false
        Thumbprint     = ""
        Domains        = @()
    } | ConvertTo-Json -Depth 5
    return
}

$listener = Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $listener) {
    [pscustomobject]@{
        ServiceRunning = $true
        Listening443   = $false
        Thumbprint     = ""
        Domains        = @()
    } | ConvertTo-Json -Depth 5
    return
}

$thumbprint = ""
$domains = @()
try {
    $remoteAccess = Get-RemoteAccess -ErrorAction Stop
    if ($remoteAccess -and $remoteAccess.SslCertificate -and $remoteAccess.SslCertificate.Thumbprint) {
        $thumbprint = ($remoteAccess.SslCertificate.Thumbprint -replace '\s', '')
    }
} catch {
}

if ($thumbprint) {
    $cert = Get-ChildItem ("Cert:\LocalMachine\My\" + $thumbprint) -ErrorAction SilentlyContinue
    if ($cert -and $cert.DnsNameList) {
        $domains = @(
            $cert.DnsNameList |
            ForEach-Object { $_.Unicode } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        )
    }
}

[pscustomobject]@{
    ServiceRunning = $true
    Listening443   = $true
    Thumbprint     = $thumbprint
    Domains        = $domains
} | ConvertTo-Json -Depth 5