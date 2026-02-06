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

function Write-LocalUninstallScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    $script = @'
Param(
    [string]$ServiceName = "certkit-agent",
    [string]$InstallDir = "C:\\Program Files\\CertKit",
    [string]$ConfigPath = "C:\\ProgramData\\CertKit\\certkit-agent\\config.json"
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Please run this script from an elevated Administrator PowerShell."
    }
}

Assert-Admin

$binPath = Join-Path $InstallDir "bin\\certkit-agent.exe"
if (Test-Path $binPath) {
    & $binPath uninstall --service-name $ServiceName --config $ConfigPath
} else {
    Write-Host "certkit-agent binary not found at $binPath. Nothing to run."
}

if (Test-Path $ConfigPath) {
    Remove-Item -Path $ConfigPath -Force -ErrorAction SilentlyContinue
}

if (-not [string]::IsNullOrWhiteSpace($env:ProgramData)) {
    $programDataCertKit = Join-Path $env:ProgramData "CertKit"
    if (Test-Path $programDataCertKit) {
        Remove-Item -Path $programDataCertKit -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
}

$regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CertKit Agent"
if (Test-Path $regPath) {
    Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Uninstall complete."
'@

    Set-Content -Path $ScriptPath -Value $script -Encoding ASCII
}

function Register-WindowsUninstallEntry {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,
        [Parameter(Mandatory = $true)]
        [string]$InstallDir,
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath,
        [Parameter(Mandatory = $true)]
        [string]$UninstallScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$InstallBinPath,
        [Parameter(Mandatory = $true)]
        [string]$Version
    )

    $regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CertKit Agent"
    $displayVersion = $Version.TrimStart("v")
    $escapedUninstallScriptPath = $UninstallScriptPath.Replace('"', '""')
    $escapedServiceName = $ServiceName.Replace('"', '""')
    $escapedInstallDir = $InstallDir.Replace('"', '""')
    $escapedConfigPath = $ConfigPath.Replace('"', '""')
    $uninstallString = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$escapedUninstallScriptPath"" -ServiceName ""$escapedServiceName"" -InstallDir ""$escapedInstallDir"" -ConfigPath ""$escapedConfigPath"""

    New-Item -Path $regPath -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "DisplayName" -Value "CertKit Agent"
    Set-ItemProperty -Path $regPath -Name "DisplayVersion" -Value $displayVersion
    Set-ItemProperty -Path $regPath -Name "Publisher" -Value "CertKit"
    Set-ItemProperty -Path $regPath -Name "InstallLocation" -Value $InstallDir
    Set-ItemProperty -Path $regPath -Name "DisplayIcon" -Value $InstallBinPath
    Set-ItemProperty -Path $regPath -Name "UninstallString" -Value $uninstallString
    Set-ItemProperty -Path $regPath -Name "QuietUninstallString" -Value $uninstallString
    Set-ItemProperty -Path $regPath -Name "NoModify" -Type DWord -Value 1
    Set-ItemProperty -Path $regPath -Name "NoRepair" -Type DWord -Value 1
    Set-ItemProperty -Path $regPath -Name "InstallDate" -Value (Get-Date).ToString("yyyyMMdd")
}

Assert-Admin

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host ""
Write-Host "Installing CertKit Agent..."
Write-Host ""

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
    if ($hadExistingService) {
        Write-Host "Stopping existing service '$ServiceName' before upgrade"
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3

        $stoppedService = Get-Service -Name $ServiceName -ErrorAction Stop
        if ($stoppedService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            throw "Service '$ServiceName' failed to stop."
        }
    }

    if (Test-Path $installBin) {
        Write-Host "Updating binary at $installBin"
    } else {
        Write-Host "Installing binary to $installBin"
    }
    Copy-Item -Force -Path $binPath -Destination $installBin

    $configDir = Split-Path -Parent $ConfigPath
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null

    if (-not (Test-Path $ConfigPath) -and [string]::IsNullOrWhiteSpace($env:REGISTRATION_KEY)) {
        throw "REGISTRATION_KEY is required for first install when config is missing."
    }

    Write-Host "Installing Windows service"
    & $installBin install --service-name $ServiceName --config $ConfigPath

    $uninstallScript = Join-Path $binDir "uninstall.ps1"
    Write-Host "Writing uninstall script to $uninstallScript"
    Write-LocalUninstallScript -ScriptPath $uninstallScript

    Write-Host "Registering Add/Remove Programs entry"
    Register-WindowsUninstallEntry -ServiceName $ServiceName -InstallDir $InstallDir -ConfigPath $ConfigPath -UninstallScriptPath $uninstallScript -InstallBinPath $installBin -Version $Version

    Write-Host "Starting service '$ServiceName'"
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $runningService = Get-Service -Name $ServiceName -ErrorAction Stop
    if ($runningService.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
        throw "Service '$ServiceName' failed to start."
    }

    if (-not [string]::IsNullOrWhiteSpace($env:REGISTRATION_KEY)) {
        $appId = ($env:REGISTRATION_KEY -split "\.")[0]
        Write-Host "Done. Service '$ServiceName' should be running."
        Write-Host ""
        Write-Host "Authorize and configure this agent: https://app.certkit.io/app/$appId/agents/"
        Write-Host ""
    } else {
        Write-Host "Done. Service '$ServiceName' should be running."
        Write-Host ""
        Write-Host "Finish configuring this agent in the CertKit UI: https://app.certkit.io"
        Write-Host ""
    }
} finally {
    if (Test-Path $tmp) {
        Remove-Item -Recurse -Force $tmp
    }
}
