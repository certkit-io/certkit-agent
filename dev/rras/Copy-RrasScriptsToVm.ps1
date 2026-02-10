param(
    [string]$VmName = "certkit-rras",
    [string]$SourcePath = "C:\Source\CertKitOther\certkit-agent\dev\rras",
    [string]$LocalBinaryPath = "",
    [string]$DestinationPath = "C:\dev\rras",
    [string]$Username = "Administrator",
    [Parameter(Mandatory = $true)]
    [string]$Password
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $SourcePath)) {
    throw "Source path not found: $SourcePath"
}

if ([string]::IsNullOrWhiteSpace($LocalBinaryPath)) {
    $repoRoot = Split-Path -Parent (Split-Path -Parent (Resolve-Path $SourcePath))
    $LocalBinaryPath = Join-Path $repoRoot "dist\bin\certkit-agent_windows_amd64.exe"
}

if (-not (Test-Path $LocalBinaryPath)) {
    throw "Local agent binary not found: $LocalBinaryPath"
}

$secure = ConvertTo-SecureString -String $Password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($Username, $secure)

$itemsToCopy = @(
    "Configure-Rras.ps1",
    "Verify-Rras.ps1",
    "README.md"
)

$session = New-PSSession -VMName $VmName -Credential $cred
try {
    Invoke-Command -Session $session -ScriptBlock {
        param($dest)
        if (-not (Test-Path $dest)) {
            New-Item -ItemType Directory -Force -Path $dest | Out-Null
        }
    } -ArgumentList $DestinationPath

    foreach ($item in $itemsToCopy) {
        $path = Join-Path $SourcePath $item
        if (-not (Test-Path $path)) {
            throw "Required file not found: $path"
        }
        Copy-Item -ToSession $session -Path $path -Destination $DestinationPath -Force
    }

    Copy-Item -ToSession $session -Path $LocalBinaryPath -Destination $DestinationPath -Force
} finally {
    if ($session) {
        Remove-PSSession $session
    }
}

Write-Host "Copied RRAS scripts and local binary to $DestinationPath in VM '$VmName'."
