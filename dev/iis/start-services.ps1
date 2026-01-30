$ErrorActionPreference = "Stop"

$serviceName = if ($env:CERTKIT_SERVICE_NAME) { $env:CERTKIT_SERVICE_NAME } else { "certkit-agent" }
$configPath = if ($env:CERTKIT_CONFIG_PATH) { $env:CERTKIT_CONFIG_PATH } else { "C:\\ProgramData\\CertKit\\certkit-agent\\config.json" }
$source = if ($env:CERTKIT_AGENT_SOURCE) { $env:CERTKIT_AGENT_SOURCE } else { "release" }
$version = $env:CERTKIT_VERSION

Write-Host "Starting IIS + CertKit Agent (source=$source)"

$agentIdPath = "C:\\ProgramData\\CertKit\\agent-id"
$agentId = "9b8c6baf-9c28-4c0a-8af1-1f2cc45e7b1a"
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $agentIdPath) | Out-Null
Set-Content -Path $agentIdPath -Value $agentId -Encoding ASCII

if ($source -eq "release") {
    if ($version) {
        & C:\app\install.ps1 -ServiceName $serviceName -ConfigPath $configPath -Version $version
    } else {
        & C:\app\install.ps1 -ServiceName $serviceName -ConfigPath $configPath
    }
} elseif ($source -eq "local") {
    $bin = if ($env:CERTKIT_AGENT_BINARY) { $env:CERTKIT_AGENT_BINARY } else { "C:\\opt\\certkit-agent\\certkit-agent.exe" }
    if (-not (Test-Path $bin)) {
        throw "Local binary not found at $bin. Set CERTKIT_AGENT_BINARY or mount the file."
    }
    & $bin install --service-name $serviceName --config $configPath
} else {
    throw "Unsupported CERTKIT_AGENT_SOURCE: $source"
}

Import-Module WebAdministration
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -eq "Certkit Dev" } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -DnsName @("iis-box", "localhost", "test.certkit.io") -CertStoreLocation "Cert:\\LocalMachine\\My" -FriendlyName "Certkit Dev"
}

$defaultSite = "Default Web Site"
$httpsBinding = Get-WebBinding -Name $defaultSite -Protocol "https" -ErrorAction SilentlyContinue
if (-not $httpsBinding) {
    New-WebBinding -Name $defaultSite -Protocol "https" -Port 443 -IPAddress "*"
    $binding = Get-WebBinding -Name $defaultSite -Protocol "https" | Select-Object -First 1
    $binding.AddSslCertificate($cert.Thumbprint, "MY")
    Write-Host "Added HTTPS binding for $defaultSite ($($cert.Thumbprint))."
}

$certkitSite = "Certkit Web Site"
$certkitPath = "C:\\inetpub\\certkit"
if (-not (Test-Path $certkitPath)) {
    New-Item -ItemType Directory -Force -Path $certkitPath | Out-Null
}
if (-not (Get-Website -Name $certkitSite -ErrorAction SilentlyContinue)) {
    New-Website -Name $certkitSite -PhysicalPath $certkitPath -Port 80 -HostHeader "test.certkit.io" | Out-Null
    Get-WebBinding -Name $certkitSite -Protocol "http" -ErrorAction SilentlyContinue | Remove-WebBinding
}
$certkitBinding = Get-WebBinding -Name $certkitSite -Protocol "https" -ErrorAction SilentlyContinue |
    Where-Object { $_.bindingInformation -like "*:44300:test.certkit.io" } |
    Select-Object -First 1
if (-not $certkitBinding) {
    New-WebBinding -Name $certkitSite -Protocol "https" -Port 44300 -HostHeader "test.certkit.io" -IPAddress "*" -SslFlags 1
} else {
    Set-WebBinding -Name $certkitSite -Port 44300 -HostHeader "test.certkit.io" -PropertyName "sslFlags" -Value 1
}
$sslBindingPath = "IIS:\\SslBindings\\0.0.0.0!44300!test.certkit.io"
if (-not (Test-Path $sslBindingPath)) {
    $sslBindingPath = "IIS:\\SslBindings\\*!44300!test.certkit.io"
}
if (-not (Test-Path $sslBindingPath)) {
    New-Item $sslBindingPath -Thumbprint $cert.Thumbprint -SSLFlags 1 | Out-Null
} else {
    # Set-ItemProperty -Path $sslBindingPath -Name Thumbprint -Value $cert.Thumbprint
    # Set-ItemProperty -Path $sslBindingPath -Name SSLFlags -Value 1
}
Write-Host "Added HTTPS binding for $certkitSite ($($cert.Thumbprint))."

Start-Service W3SVC

$stopServices = {
    Write-Host "Stopping services..."
    try { Stop-Service $serviceName -Force -ErrorAction SilentlyContinue } catch {}
    try { Stop-Service W3SVC -Force -ErrorAction SilentlyContinue } catch {}
}

try {
    powershell -NoProfile -Command "Get-Content C:\dev\iis\certkit-agent.log -Tail 20 -Wait"
} finally {
    & $stopServices
}
