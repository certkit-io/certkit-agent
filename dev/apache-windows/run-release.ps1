Param(
    [string]$ApiBase = $env:CERTKIT_API_BASE,
    [string]$RegistrationKey = $env:REGISTRATION_KEY,
    [string]$Version = $env:CERTKIT_VERSION,
    [string]$ServiceName = $env:CERTKIT_SERVICE_NAME,
    [string]$ConfigPath = $env:CERTKIT_CONFIG_PATH
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
if ($ServiceName) { $env:CERTKIT_SERVICE_NAME = $ServiceName }
if ($ConfigPath) { $env:CERTKIT_CONFIG_PATH = $ConfigPath }

$composeBase = Join-Path $scriptDir "apache-windows.docker-compose.yml"

Write-Host "Starting Windows Apache dev stack via docker compose (release)"
Write-Host "  CERTKIT_API_BASE=$env:CERTKIT_API_BASE"
Write-Host "  CERTKIT_AGENT_SOURCE=$env:CERTKIT_AGENT_SOURCE"
if ($Version) { Write-Host "  CERTKIT_VERSION=$env:CERTKIT_VERSION" }

$env:COMPOSE_COMPATIBILITY = "1"
& docker compose -f $composeBase up --build
