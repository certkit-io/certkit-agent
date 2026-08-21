Param(
    [string]$Version = $env:VERSION,
    [string]$ServiceName = "certkit-agent",
    [string]$InstallDir = "C:\\Program Files\\CertKit",
    [string]$ConfigPath = "C:\\ProgramData\\CertKit\\certkit-agent\\config.json",
    [string]$Owner = "certkit-io",
    [string]$Repo = "certkit-agent",
    # Github is blocked on many customer networks, so downloads go through the CertKit github proxy
    [string]$GithubProxyBase = "https://app.certkit.io"
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

function Assert-SupportedWindows {
    # The agent is built with Go 1.21+, which requires Windows 10 / Windows Server 2016 or later.
    # On older releases (e.g. Server 2008 R2 / 2012 R2) the binary crashes at startup with a cryptic
    # "Exception 0xc0000005 ... runtime.asmstdcall" before any of our code runs, so fail early instead.
    $osVersion = $null
    $osCaption = "unknown Windows version"
    try {
        # WMI reports the true version; [Environment]::OSVersion can be capped at 6.2 on unmanifested hosts.
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $osVersion = [version]$os.Version
        if ($os.Caption) { $osCaption = $os.Caption.Trim() }
    } catch {
        $osVersion = [Environment]::OSVersion.Version
    }

    if ($osVersion.Major -lt 10) {
        throw "CertKit Agent requires Windows 10 / Windows Server 2016 or later. Detected: $osCaption ($osVersion)."
    }
}

function Get-LatestReleaseTag {
    $uri = "$GithubProxyBase/github-api-proxy/repos/$Owner/$Repo/releases/latest"
    $latest = Invoke-RestMethod -Uri $uri -Headers @{ "User-Agent" = "certkit-agent-installer" }
    if (-not $latest) {
        throw "No releases found for $Owner/$Repo"
    }
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
Assert-SupportedWindows

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

$baseUrl = "$GithubProxyBase/github-proxy/$Owner/$Repo/releases/download/$Version"
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
