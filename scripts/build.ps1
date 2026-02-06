Param(
    [string]$Out = "dist\\bin\\certkit-agent_windows_amd64.exe",
    [string]$Version = $env:VERSION,
    [string]$Commit = $env:COMMIT,
    [string]$BuildDate = $env:BUILD_DATE
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $root
try {
    if ([string]::IsNullOrWhiteSpace($Version)) {
        try {
            $Version = (git describe --tags --always --dirty)
        } catch {
            $Version = "dev"
        }
    }

    if ([string]::IsNullOrWhiteSpace($Commit)) {
        try {
            $Commit = (git rev-parse --short HEAD)
        } catch {
            $Commit = "none"
        }
    }

    if ([string]::IsNullOrWhiteSpace($BuildDate)) {
        $BuildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    }

    $outDir = Split-Path -Parent $Out
    if (-not [string]::IsNullOrWhiteSpace($outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }

    $ldflags = "-s -w -X main.version=$Version -X main.commit=$Commit -X main.date=$BuildDate"

    $oldCgoEnabled = $env:CGO_ENABLED
    $oldGoos = $env:GOOS
    $oldGoarch = $env:GOARCH
    try {
        $env:CGO_ENABLED = "0"
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"

        Write-Host "Building windows/amd64 -> $Out"
        go build -trimpath -ldflags $ldflags -o $Out .\cmd\certkit-agent
    } finally {
        $env:CGO_ENABLED = $oldCgoEnabled
        $env:GOOS = $oldGoos
        $env:GOARCH = $oldGoarch
    }
} finally {
    Pop-Location
}
