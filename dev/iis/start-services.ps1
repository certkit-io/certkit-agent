$ErrorActionPreference = "Stop"

$serviceName = if ($env:CERTKIT_SERVICE_NAME) { $env:CERTKIT_SERVICE_NAME } else { "certkit-agent" }
$configPath = if ($env:CERTKIT_CONFIG_PATH) { $env:CERTKIT_CONFIG_PATH } else { "C:\\ProgramData\\CertKit\\certkit-agent\\config.json" }
$source = if ($env:CERTKIT_AGENT_SOURCE) { $env:CERTKIT_AGENT_SOURCE } else { "release" }

Write-Host "Starting IIS + CertKit Agent (source=$source)"

if ($source -eq "release") {
    & C:\app\install.ps1 -ServiceName $serviceName -ConfigPath $configPath
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

if (Test-Path "C:\\ServiceMonitor.exe") {
    Write-Host "IIS started. Following w3svc with ServiceMonitor."
    & C:\ServiceMonitor.exe w3svc
} else {
    Write-Host "IIS started. ServiceMonitor not found; keeping container alive."
    while ($true) { Start-Sleep -Seconds 60 }
}
