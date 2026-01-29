$ErrorActionPreference = "Stop"

$serviceName = if ($env:CERTKIT_SERVICE_NAME) { $env:CERTKIT_SERVICE_NAME } else { "certkit-agent" }
$configPath = if ($env:CERTKIT_CONFIG_PATH) { $env:CERTKIT_CONFIG_PATH } else { "C:\\ProgramData\\CertKit\\certkit-agent\\config.json" }
$source = if ($env:CERTKIT_AGENT_SOURCE) { $env:CERTKIT_AGENT_SOURCE } else { "release" }
$version = $env:CERTKIT_VERSION

Write-Host "Starting IIS + CertKit Agent (source=$source)"

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
