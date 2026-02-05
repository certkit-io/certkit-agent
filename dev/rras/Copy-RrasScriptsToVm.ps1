param(
    [string]$VmName = "certkit-rras",
    [string]$SourcePath = "C:\Source\CertKitOther\certkit-agent\dev\rras",
    [string]$DestinationPath = "C:\dev\rras",
    [string]$Username = "Administrator",
    [Parameter(Mandatory = $true)]
    [string]$Password
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $SourcePath)) {
    throw "Source path not found: $SourcePath"
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
} finally {
    if ($session) {
        Remove-PSSession $session
    }
}

Write-Host "Copied $SourcePath to $DestinationPath in VM '$VmName'."
