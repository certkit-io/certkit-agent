$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeBase = Join-Path $scriptDir "apache-windows.docker-compose.yml"
$composeLocal = Join-Path $scriptDir "apache-windows.local.docker-compose.yml"

$env:COMPOSE_COMPATIBILITY = "1"

Write-Host "Stopping Windows Apache dev stack via docker compose"
& docker compose -f $composeBase -f $composeLocal stop
Start-Sleep -Seconds 5
& docker compose -f $composeBase -f $composeLocal down --remove-orphans --timeout 30
