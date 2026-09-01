Param(
    [string]$Out = "dist\bin\certkit-agent_windows_amd64.exe",
    [string]$LinuxOut = "dist\bin\certkit-agent_linux_amd64",
    [string]$Version = $env:VERSION,
    [string]$Commit = $env:COMMIT,
    [string]$BuildDate = $env:BUILD_DATE,
    # Also build the (unsigned) MSI. Requires the WiX CLI:
    #   dotnet tool install --global wix --version 6.0.2
    #   wix extension add -g WixToolset.Util.wixext/6.0.2
    #   wix extension add -g WixToolset.UI.wixext/6.0.2
    [switch]$Msi
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

    # Windows resources (.syso): icon + VERSIONINFO + manifest. The generated
    # file is suffixed _windows_amd64 so only the windows build links it.
    # Accept X.Y.Z or a prerelease tag X.Y.Z-<suffix>, but NOT git-describe
    # output (1.11.0-35-gabc123[-dirty]) - dev builds keep 0.0.0.
    $base = $Version.TrimStart("v")
    $verNumeric = "0.0.0"
    if ($base -match '^(\d+\.\d+\.\d+)(-[0-9A-Za-z][0-9A-Za-z.-]*)?$' -and
        $base -notmatch '-\d+-g[0-9a-f]+(-dirty)?$' -and
        $base -notmatch '-dirty$') {
        $verNumeric = $Matches[1]
    }
    Write-Host "Generating Windows resources (go-winres, version $verNumeric)"
    go run github.com/tc-hib/go-winres@v0.3.3 make --in winres/winres.json --arch amd64 --product-version $verNumeric --file-version $verNumeric --out cmd/certkit-agent/rsrc
    if ($LASTEXITCODE -ne 0) {
        throw "go-winres failed with exit code $LASTEXITCODE"
    }

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

    if ($Msi) {
        if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
            throw "WiX CLI not found. Install it with:`n  dotnet tool install --global wix --version 6.0.2`n  wix extension add -g WixToolset.Util.wixext/6.0.2`n  wix extension add -g WixToolset.UI.wixext/6.0.2"
        }
        if ($verNumeric -eq "0.0.0") {
            Write-Warning "MSI ProductVersion is 0.0.0 (no clean vX.Y.Z version available). For install/upgrade testing pass e.g. -Version v1.99.0 and bump it per build - MSIs with identical versions install side by side instead of upgrading."
        }
        $msiOut = "dist\msi\certkit-agent_windows_amd64.msi"
        New-Item -ItemType Directory -Force -Path (Split-Path -Parent $msiOut) | Out-Null
        Write-Host "Building MSI (version $verNumeric) -> $msiOut"
        wix build packaging\windows\Package.wxs packaging\windows\CertKitUI.wxs `
            -arch x64 `
            -d "Version=$verNumeric" `
            -d "AgentExe=$Out" `
            -ext WixToolset.Util.wixext `
            -ext WixToolset.UI.wixext `
            -o $msiOut
        if ($LASTEXITCODE -ne 0) {
            throw "wix build failed with exit code $LASTEXITCODE"
        }
    }
} finally {
    Pop-Location
}
