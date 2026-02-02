$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Param(
    [ValidateSet("socket","watch","pid")]
    [string]$Mode = "socket"
)

$composeBase = Join-Path $scriptDir "docker-sidecar.docker-compose.yml"
$composeLocal = Join-Path $scriptDir "docker-sidecar.local.docker-compose.yml"
if ($Mode -eq "watch") {
    $composeBase = Join-Path $scriptDir "docker-sidecar.watch.docker-compose.yml"
} elseif ($Mode -eq "pid") {
    $composeBase = Join-Path $scriptDir "docker-sidecar.pid.docker-compose.yml"
}

Write-Host "Stopping Docker sidecar dev stack via docker compose (mode=$Mode)"
& docker compose -f $composeBase -f $composeLocal stop
Start-Sleep -Seconds 5
& docker compose -f $composeBase -f $composeLocal down --remove-orphans --timeout 30
