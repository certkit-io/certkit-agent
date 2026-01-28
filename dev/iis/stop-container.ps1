$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$composeBase = Join-Path $scriptDir "iis.docker-compose.yml"
$composeLocal = Join-Path $scriptDir "iis.local.docker-compose.yml"

$env:COMPOSE_COMPATIBILITY = "1"

Write-Host "Stopping Windows IIS dev stack via docker compose"
& docker compose -f $composeBase -f $composeLocal down --remove-orphans
