param(
  [switch]$Release
)

$ErrorActionPreference = "Stop"

$devRoot = $PSScriptRoot
$mode = if ($Release) { "release" } else { "local" }

$composeFiles = @(
  "nginx\nginx.docker-compose.yml",
  "apache\apache.docker-compose.yml",
  "litespeed\litespeed.docker-compose.yml",
  "haproxy\haproxy.docker-compose.yml"
)

function Set-EnvValue {
  param(
    [string]$Path,
    [string]$Key,
    [string]$Value
  )

  if (-not (Test-Path $Path)) {
    $seed = @(
      "CERTKIT_API_BASE=YOUR_API_BASE",
      "REGISTRATION_KEY=YOUR_REGISTRATION_KEY"
    )
    Set-Content -Path $Path -Value $seed
  }

  $lines = Get-Content $Path
  $filtered = $lines | Where-Object { $_ -notmatch "^\s*$Key=" }
  $filtered += "$Key=$Value"
  Set-Content -Path $Path -Value $filtered
}

foreach ($composeFile in $composeFiles) {
  $envPath = Join-Path $devRoot ($composeFile.Split("\")[0] + "\.env")
  Set-EnvValue -Path $envPath -Key "CERTKIT_AGENT_SOURCE" -Value $mode
}

foreach ($composeFile in $composeFiles) {
  $fullPath = Join-Path $devRoot $composeFile
  Write-Host "Starting $composeFile (CERTKIT_AGENT_SOURCE=$mode)"
  docker compose -f $fullPath up --build -d
}
