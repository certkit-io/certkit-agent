Param(
    [string]$Version = "",
    [string]$ServiceName = "certkit-agent",
    [string]$InstallDir = "C:\\Program Files\\CertKit",
    [string]$ConfigPath = "C:\\ProgramData\\CertKit\\certkit-agent\\config.json",
    [string]$Owner = "certkit-io",
    [string]$Repo = "certkit-agent"
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run this script from an elevated Administrator PowerShell."
    }
}

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { throw "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE" }
    }
}

function Get-LatestReleaseTag {
    $uri = "https://api.github.com/repos/$Owner/$Repo/releases"
    $releases = Invoke-RestMethod -Uri $uri -Headers @{ "User-Agent" = "certkit-agent-installer" }
    if (-not $releases) {
        throw "No releases found for $Owner/$Repo"
    }
    $latest = $releases | Sort-Object published_at -Descending | Select-Object -First 1
    if (-not $latest.tag_name) {
        throw "Failed to determine latest release tag"
    }
    return $latest.tag_name
}

function Wait-ServiceState {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [System.ServiceProcess.ServiceControllerStatus]$State,
        [int]$TimeoutSeconds = 30
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc) {
            return $false
        }
        if ($svc.Status -eq $State) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }

    return $false
}

Assert-Admin

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$arch = Get-Arch
$binName = "certkit-agent"
$assetBin = "${binName}_windows_${arch}.exe"
$assetSha = "${binName}_SHA256SUMS.txt"

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-LatestReleaseTag
}

Write-Host "Using release tag: $Version"

$baseUrl = "https://github.com/$Owner/$Repo/releases/download/$Version"
$tmp = Join-Path $env:TEMP ("certkit-agent-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    $binPath = Join-Path $tmp $assetBin
    $shaPath = Join-Path $tmp $assetSha

    Write-Host "Downloading $assetBin"
    Invoke-WebRequest -Uri "$baseUrl/$assetBin" -OutFile $binPath

    Write-Host "Downloading $assetSha"
    Invoke-WebRequest -Uri "$baseUrl/$assetSha" -OutFile $shaPath

    Write-Host "Verifying checksum"
    $shaLine = Get-Content $shaPath | Where-Object { $_ -match [regex]::Escape($assetBin) } | Select-Object -First 1
    if (-not $shaLine) {
        throw "Checksum entry not found for $assetBin"
    }
    $expected = ($shaLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $binPath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "Checksum mismatch for $assetBin"
    }

    $binDir = Join-Path $InstallDir "bin"
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    $installBin = Join-Path $binDir "certkit-agent.exe"

    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $hadExistingService = $null -ne $existingService
    if ($hadExistingService -and $existingService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        Write-Host "Stopping existing service '$ServiceName' before upgrade"
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
        if (-not (Wait-ServiceState -Name $ServiceName -State ([System.ServiceProcess.ServiceControllerStatus]::Stopped) -TimeoutSeconds 60)) {
            throw "Service '$ServiceName' did not stop within timeout."
        }
    }

    Write-Host "Installing binary to $installBin"
    Copy-Item -Force -Path $binPath -Destination $installBin

    $configDir = Split-Path -Parent $ConfigPath
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null

    if (-not (Test-Path $ConfigPath) -and [string]::IsNullOrWhiteSpace($env:REGISTRATION_KEY)) {
        throw "REGISTRATION_KEY is required for first install when config is missing."
    }

    Write-Host "Installing Windows service"
    & $installBin install --service-name $ServiceName --config $ConfigPath

    if (-not (Wait-ServiceState -Name $ServiceName -State ([System.ServiceProcess.ServiceControllerStatus]::Running) -TimeoutSeconds 30)) {
        Write-Host "Service '$ServiceName' was not running after install; starting it now"
        Start-Service -Name $ServiceName -ErrorAction Stop
    }

    if (-not [string]::IsNullOrWhiteSpace($env:REGISTRATION_KEY)) {
        $appId = ($env:REGISTRATION_KEY -split "\.")[0]
        Write-Host "Done. Service '$ServiceName' should be running."
        Write-Host "Authorize and configure this agent: https://app.certkit.io/app/$appId/agents/"
    } else {
        Write-Host "Done. Service '$ServiceName' should be running."
        Write-Host "Finish configuring this agent in the CertKit UI: https://app.certkit.io"
    }
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}
