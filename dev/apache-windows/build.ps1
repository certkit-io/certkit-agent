Param(
    [string]$Out = "dist\\bin\\certkit-agent_windows_amd64.exe"
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..\\..")
Push-Location $root
try {
    $version = if ($env:VERSION) { $env:VERSION } else { try { (git describe --tags --always --dirty) } catch { "dev" } }
    $commit = if ($env:COMMIT) { $env:COMMIT } else { try { (git rev-parse --short HEAD) } catch { "none" } }
    $date = if ($env:BUILD_DATE) { $env:BUILD_DATE } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }

    $ldflags = "-s -w -X main.version=$version -X main.commit=$commit -X main.date=$date"

    $outPath = Resolve-Path -Path (Split-Path -Parent $Out) -ErrorAction SilentlyContinue
    if (-not $outPath) {
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
    }

    Write-Host "Building Windows binary -> $Out"
    $env:CGO_ENABLED = "0"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    go build -trimpath -ldflags $ldflags -o $Out .\cmd\certkit-agent
} finally {
    Pop-Location
}
