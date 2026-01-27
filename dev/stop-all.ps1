param()

$ErrorActionPreference = "Stop"

$devRoot = $PSScriptRoot
$composeFiles = @(
  "nginx\nginx.docker-compose.yml",
  "apache\apache.docker-compose.yml",
  "litespeed\litespeed.docker-compose.yml",
  "haproxy\haproxy.docker-compose.yml"
)

foreach ($composeFile in $composeFiles) {
  $fullPath = Join-Path $devRoot $composeFile
  if (-not (Test-Path $fullPath)) {
    Write-Host "Skipping missing compose file: $composeFile"
    continue
  }
  Write-Host "Stopping $composeFile"
  docker compose -f $fullPath down
}
