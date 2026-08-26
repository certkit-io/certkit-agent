Param(
    [string]$Version = $env:VERSION,
    [string]$ServiceName = "certkit-agent",
    [string]$InstallDir = "C:\Program Files\CertKit",
    [string]$ConfigPath = "C:\ProgramData\CertKit\certkit-agent\config.json",
    [string]$Owner = "certkit-io",
    [string]$Repo = "certkit-agent",
    # Github is blocked on many customer networks, so downloads go through the CertKit github proxy
    [string]$GithubProxyBase = "https://app.certkit.io",
    # Use the legacy raw-binary install path instead of the MSI
    [switch]$Binary
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

function Assert-ChecksumOk {
    param(
        [Parameter(Mandatory = $true)][string]$ShaFilePath,
        [Parameter(Mandatory = $true)][string]$AssetName,
        [Parameter(Mandatory = $true)][string]$FilePath
    )

    $shaLine = Get-Content $ShaFilePath | Where-Object { $_ -match [regex]::Escape($AssetName) } | Select-Object -First 1
    if (-not $shaLine) {
        throw "Checksum entry not found for $AssetName"
    }
    $expected = ($shaLine -split "\s+")[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path $FilePath).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "Checksum mismatch for $AssetName"
    }
}

function Test-MsiProductInstalled {
    # An MSI install registers under a GUID-named uninstall key; the legacy
    # script wrote a literal "CertKit Agent" key instead.
    $roots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )
    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($key in (Get-ChildItem -Path $root -ErrorAction SilentlyContinue)) {
            if ($key.PSChildName -notmatch '^\{[0-9A-Fa-f\-]+\}$') { continue }
            $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
            if ($props.DisplayName -eq "CertKit Agent") { return $true }
        }
    }
    return $false
}

function Invoke-LegacyMigration {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$InstallDir
    )

    Write-Host "Migrating existing script-based install to the MSI"
    Write-Host "Existing configuration is preserved; no new REGISTRATION_KEY is needed."

    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw "Service '$ServiceName' failed to stop for migration."
    }

    # The MSI must own the service; installing over a pre-existing service it
    # did not create misbehaves, so delete the script-created one first.
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1

    $legacyArp = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent"
    if (Test-Path $legacyArp) {
        Remove-Item -Path $legacyArp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Older installs baked doubled backslashes into paths; normalize before use.
    $binDir = Join-Path ($InstallDir -replace '\\\\', '\') "bin"
    foreach ($name in @("uninstall.ps1", "certkit-agent.old.exe", "certkit-agent.new.exe")) {
        $p = Join-Path $binDir $name
        if (Test-Path $p) {
            Remove-Item -Path $p -Force -ErrorAction SilentlyContinue
        }
    }
}

# --- Legacy raw-binary install path (also used with -Binary) -----------------

function Write-LocalUninstallScript {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath
    )

    $script = @'
Param(
    [string]$ServiceName = "certkit-agent",
    [string]$InstallDir = "C:\Program Files\CertKit",
    [string]$ConfigPath = "C:\ProgramData\CertKit\certkit-agent\config.json"
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

$binPath = Join-Path $InstallDir "bin\certkit-agent.exe"
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

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent"
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

    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent"
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

function Install-LegacyBinary {
    param(
        [Parameter(Mandatory = $true)][string]$Arch,
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$TempDir
    )

    $binName = "certkit-agent"
    $assetBin = "${binName}_windows_${Arch}.exe"
    $assetSha = "${binName}_SHA256SUMS.txt"

    $binPath = Join-Path $TempDir $assetBin
    $shaPath = Join-Path $TempDir $assetSha

    Write-Host "Downloading $assetBin"
    Invoke-WebRequest -Uri "$BaseUrl/$assetBin" -OutFile $binPath

    Write-Host "Downloading $assetSha"
    Invoke-WebRequest -Uri "$BaseUrl/$assetSha" -OutFile $shaPath

    Write-Host "Verifying checksum"
    Assert-ChecksumOk -ShaFilePath $shaPath -AssetName $assetBin -FilePath $binPath

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
}

# --- MSI install path (default) ----------------------------------------------

function Install-Msi {
    param(
        [Parameter(Mandatory = $true)][string]$Arch,
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$TempDir
    )

    if ($Arch -ne "amd64") {
        Write-Host "Note: installing the amd64 MSI on $Arch (runs under x64 emulation)."
    }

    $assetMsi = "certkit-agent_windows_amd64.msi"
    $assetSha = "certkit-agent_SHA256SUMS.txt"

    # Fail fast before downloading anything.
    if (-not (Test-Path $ConfigPath) -and [string]::IsNullOrWhiteSpace($env:REGISTRATION_KEY)) {
        throw "REGISTRATION_KEY is required for first install when config is missing."
    }

    $msiPath = Join-Path $TempDir $assetMsi
    $shaPath = Join-Path $TempDir $assetSha

    Write-Host "Downloading $assetMsi"
    Invoke-WebRequest -Uri "$BaseUrl/$assetMsi" -OutFile $msiPath

    Write-Host "Downloading $assetSha"
    Invoke-WebRequest -Uri "$BaseUrl/$assetSha" -OutFile $shaPath

    Write-Host "Verifying checksum"
    Assert-ChecksumOk -ShaFilePath $shaPath -AssetName $assetMsi -FilePath $msiPath

    # A service that exists without an MSI product registration was created by
    # the legacy script (or `certkit-agent install` by hand); the MSI must not
    # install over it.
    $existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($existingService -and -not (Test-MsiProductInstalled)) {
        Invoke-LegacyMigration -ServiceName $ServiceName -InstallDir $InstallDir
    }

    $logPath = Join-Path $env:TEMP "certkit-agent-msi-install.log"
    $msiArgs = @(
        "/i", "`"$msiPath`"",
        "/qn", "/norestart",
        "/l*v", "`"$logPath`""
    )
    if (-not [string]::IsNullOrWhiteSpace($env:REGISTRATION_KEY)) {
        $msiArgs += "REGISTRATIONKEY=`"$($env:REGISTRATION_KEY)`""
    }
    $normalizedInstallDir = $InstallDir -replace '\\\\', '\'
    if ($normalizedInstallDir -ne "C:\Program Files\CertKit") {
        $msiArgs += "CERTKITDIR=`"$normalizedInstallDir`""
    }

    Write-Host "Installing CertKit Agent MSI (log: $logPath)"
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
    if ($proc.ExitCode -eq 3010) {
        Write-Host "Install succeeded; Windows recommends a reboot to complete (exit code 3010)."
    } elseif ($proc.ExitCode -ne 0) {
        throw "MSI install failed with exit code $($proc.ExitCode). See log: $logPath"
    }

    # The MSI starts the service without waiting; verify it actually runs.
    $deadline = (Get-Date).AddSeconds(20)
    $running = $false
    while ((Get-Date) -lt $deadline) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {
            $running = $true
            break
        }
        if ($svc -and $svc.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
        }
        Start-Sleep -Seconds 2
    }
    if (-not $running) {
        throw "Service '$ServiceName' failed to start. MSI log: $logPath"
    }
}

# --- Main --------------------------------------------------------------------

Assert-Admin

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host ""
Write-Host "Installing CertKit Agent..."
Write-Host ""

$arch = Get-Arch

if (-not $Binary) {
    # The MSI bakes in the service name and config path; only -InstallDir can
    # be overridden on the MSI path. Use -Binary for the other overrides.
    if ($ServiceName -ne "certkit-agent" -or ($ConfigPath -replace '\\\\', '\') -ne "C:\ProgramData\CertKit\certkit-agent\config.json") {
        throw "Custom -ServiceName / -ConfigPath values require the -Binary install path."
    }
}

if ([string]::IsNullOrWhiteSpace($Version)) {
    $Version = Get-LatestReleaseTag
}

Write-Host "Using release tag: $Version"

$baseUrl = "$GithubProxyBase/github-proxy/$Owner/$Repo/releases/download/$Version"
$tmp = Join-Path $env:TEMP ("certkit-agent-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

try {
    if ($Binary) {
        Install-LegacyBinary -Arch $arch -BaseUrl $baseUrl -TempDir $tmp
    } else {
        Install-Msi -Arch $arch -BaseUrl $baseUrl -TempDir $tmp
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
