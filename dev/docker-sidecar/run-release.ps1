Param(
    [string]$ApiBase = $env:CERTKIT_API_BASE,
    [string]$RegistrationKey = $env:REGISTRATION_KEY,
    [string]$Version = $env:CERTKIT_VERSION,
    [ValidateSet("socket","watch","pid")]
    [string]$Mode = "socket"
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $ApiBase) {
    throw "CERTKIT_API_BASE is required (pass -ApiBase or set env var)."
}
if (-not $RegistrationKey) {
    throw "REGISTRATION_KEY is required (pass -RegistrationKey or set env var)."
}

$env:CERTKIT_API_BASE = $ApiBase
$env:REGISTRATION_KEY = $RegistrationKey
$env:CERTKIT_AGENT_SOURCE = "release"
if ($Version) { $env:CERTKIT_VERSION = $Version }

$composeBase = Join-Path $scriptDir "docker-sidecar.docker-compose.yml"
if ($Mode -eq "watch") {
    $composeBase = Join-Path $scriptDir "docker-sidecar.watch.docker-compose.yml"
} elseif ($Mode -eq "pid") {
    $composeBase = Join-Path $scriptDir "docker-sidecar.pid.docker-compose.yml"
}

Write-Host "Starting Docker sidecar dev stack via docker compose (release, mode=$Mode)"
Write-Host "  CERTKIT_API_BASE=$env:CERTKIT_API_BASE"
Write-Host "  CERTKIT_AGENT_SOURCE=$env:CERTKIT_AGENT_SOURCE"
if ($Version) { Write-Host "  CERTKIT_VERSION=$env:CERTKIT_VERSION" }

& docker compose -f $composeBase up --build
