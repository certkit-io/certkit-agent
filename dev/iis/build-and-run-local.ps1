Param(
    [string]$ApiBase = $env:CERTKIT_API_BASE,
    [string]$RegistrationKey = $env:REGISTRATION_KEY,
    [string]$ServiceName = $env:CERTKIT_SERVICE_NAME,
    [string]$ConfigPath = $env:CERTKIT_CONFIG_PATH,
    [string]$AgentBinary = $env:CERTKIT_AGENT_BINARY,
    [string]$BaseImage = $env:CERTKIT_WINDOWS_BASE_IMAGE
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

& (Join-Path $scriptDir "build.ps1")

if (-not $ApiBase) {
    throw "CERTKIT_API_BASE is required (pass -ApiBase or set env var)."
}
if (-not $RegistrationKey) {
    throw "REGISTRATION_KEY is required (pass -RegistrationKey or set env var)."
}

$env:CERTKIT_API_BASE = $ApiBase
$env:REGISTRATION_KEY = $RegistrationKey
$env:CERTKIT_AGENT_SOURCE = "local"
if ($ServiceName) { $env:CERTKIT_SERVICE_NAME = $ServiceName }
if ($ConfigPath) { $env:CERTKIT_CONFIG_PATH = $ConfigPath }
if ($AgentBinary) { $env:CERTKIT_AGENT_BINARY = $AgentBinary }
$defaultBase = "mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019"
if (-not $BaseImage) {
    $BaseImage = $defaultBase
}
$env:CERTKIT_WINDOWS_BASE_IMAGE = $BaseImage

$composeBase = Join-Path $scriptDir "iis.docker-compose.yml"
$composeLocal = Join-Path $scriptDir "iis.local.docker-compose.yml"

Write-Host "Starting Windows IIS dev stack via docker compose"
Write-Host "  CERTKIT_API_BASE=$env:CERTKIT_API_BASE"
Write-Host "  CERTKIT_AGENT_SOURCE=$env:CERTKIT_AGENT_SOURCE"
Write-Host "  CERTKIT_WINDOWS_BASE_IMAGE=$env:CERTKIT_WINDOWS_BASE_IMAGE"

$env:COMPOSE_COMPATIBILITY = "1"
& docker compose -f $composeBase -f $composeLocal up --build
