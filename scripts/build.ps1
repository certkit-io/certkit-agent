Param(
    [string]$Out = "dist\\bin\\certkit-agent_windows_amd64.exe",
    [string]$LinuxOut = "dist\\bin\\certkit-agent_linux_amd64",
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

    $outDirs = @(
        (Split-Path -Parent $Out),
        (Split-Path -Parent $LinuxOut)
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($dir in $outDirs) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }

    $ldflags = "-s -w -X main.version=$Version -X main.commit=$Commit -X main.date=$BuildDate"

    function Build-One {
        param(
            [Parameter(Mandatory = $true)][string]$GoOs,
            [Parameter(Mandatory = $true)][string]$GoArch,
            [Parameter(Mandatory = $true)][string]$Output
        )
        $env:CGO_ENABLED = "0"
        $env:GOOS = $GoOs
        $env:GOARCH = $GoArch
        Write-Host "Building $GoOs/$GoArch -> $Output"
        go build -trimpath -ldflags $ldflags -o $Output .\cmd\certkit-agent
    }

    $oldCgoEnabled = $env:CGO_ENABLED
    $oldGoos = $env:GOOS
    $oldGoarch = $env:GOARCH
    try {
        Build-One -GoOs "windows" -GoArch "amd64" -Output $Out
        Build-One -GoOs "linux" -GoArch "amd64" -Output $LinuxOut
    } finally {
        $env:CGO_ENABLED = $oldCgoEnabled
        $env:GOOS = $oldGoos
        $env:GOARCH = $oldGoarch
    }
} finally {
    Pop-Location
}
