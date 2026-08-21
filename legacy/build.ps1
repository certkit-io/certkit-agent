# Builds the "legacy" Windows agent for Windows Server 2008 R2 / 2012 R2 (and Win 7 / 8.1).
#
# Go 1.21+ dropped support for those OSes, so this build uses Go 1.20.14 (the last release
# that supports them) together with legacy/go.legacy.mod, which pins the dependencies to
# versions compatible with Go 1.20. The main go.mod and toolchain are not touched.
#
# One-time setup (installs the SDK side-by-side under ~/sdk/go1.20.14, does not replace `go`):
#   go install golang.org/dl/go1.20.14@latest
#   go1.20.14 download
#
# Usage:
#   .\legacy\build.ps1
#   .\legacy\build.ps1 -Out dist\bin\certkit-agent_windows_amd64_legacy.exe
Param(
    [string]$Out = "dist\bin\certkit-agent_windows_amd64_legacy.exe",
    [string]$Version = $env:VERSION,
    [string]$Commit = $env:COMMIT,
    [string]$BuildDate = $env:BUILD_DATE,
    [string]$LegacyGo = "go1.20.14"
)

$ErrorActionPreference = "Stop"

$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $root
try {
    $goCmd = Get-Command $LegacyGo -ErrorAction SilentlyContinue
    if (-not $goCmd) {
        $candidate = Join-Path (Join-Path $env:USERPROFILE "go\bin") "$LegacyGo.exe"
        if (Test-Path $candidate) {
            $goCmd = Get-Command $candidate
        } else {
            throw "$LegacyGo not found. Install it with: go install golang.org/dl/$LegacyGo@latest; $LegacyGo download"
        }
    }
    $goExe = $goCmd.Source

    $goVersion = (& $goExe version)
    if ($goVersion -notmatch "go1\.20\.") {
        throw "Expected a Go 1.20.x toolchain for the legacy build, got: $goVersion"
    }
    Write-Host "Using legacy toolchain: $goVersion"

    if ([string]::IsNullOrWhiteSpace($Version)) {
        try {
            $Version = (git describe --tags --always --dirty)
        } catch {
            $Version = "dev"
        }
    }
    # Build metadata suffix identifies the legacy variant without affecting semver ordering.
    if ($Version -notmatch "\+legacy$") {
        $Version = "$Version+legacy"
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

    $modFile = Join-Path $root "legacy\go.legacy.mod"
    $ldflags = "-s -w -X main.version=$Version -X main.commit=$Commit -X main.date=$BuildDate"

    $oldCgoEnabled = $env:CGO_ENABLED
    $oldGoos = $env:GOOS
    $oldGoarch = $env:GOARCH
    try {
        $env:CGO_ENABLED = "0"
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        Write-Host "Building legacy windows/amd64 ($Version) -> $Out"
        & $goExe build -modfile $modFile -trimpath -ldflags $ldflags -o $Out .\cmd\certkit-agent
        if ($LASTEXITCODE -ne 0) {
            throw "legacy build failed with exit code $LASTEXITCODE"
        }
    } finally {
        $env:CGO_ENABLED = $oldCgoEnabled
        $env:GOOS = $oldGoos
        $env:GOARCH = $oldGoarch
    }

    Write-Host "Built: $((go version $Out))"
} finally {
    Pop-Location
}
