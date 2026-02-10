param(
    [string]$VhdPath = (Join-Path $PSScriptRoot "downloads\\WindowsServer2022_Eval.vhd"),
    [string]$VmName = "certkit-rras",
    [string]$VmRoot = "$env:ProgramData\CertKit\dev\rras",
    [string]$SwitchName,
    [int]$MemoryStartupGB = 4,
    [int]$CpuCount = 2,
    [switch]$CopyVhd
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) {
    throw "Hyper-V PowerShell module not found. Enable Hyper-V and reopen PowerShell."
}

if (-not (Test-Path $VhdPath)) {
    throw "VHD not found: $VhdPath"
}

if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
    throw "VM already exists: $VmName"
}

if (-not $SwitchName) {
    $defaultSwitch = Get-VMSwitch -Name "Default Switch" -ErrorAction SilentlyContinue
    if ($defaultSwitch) {
        $SwitchName = $defaultSwitch.Name
    } else {
        $switches = Get-VMSwitch | Select-Object -ExpandProperty Name
        $switchList = if ($switches) { ($switches -join ", ") } else { "(none)" }
        throw "No Hyper-V switch specified and Default Switch not found. Available: $switchList"
    }
}

if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    throw "Hyper-V switch not found: $SwitchName"
}

$vmFolder = Join-Path $VmRoot $VmName
New-Item -ItemType Directory -Force -Path $vmFolder | Out-Null

$memoryStartupBytes = $MemoryStartupGB * 1GB

$usedVhdPath = $VhdPath
if ($CopyVhd) {
    $usedVhdPath = Join-Path $vmFolder (Split-Path -Leaf $VhdPath)
    Copy-Item -Path $VhdPath -Destination $usedVhdPath -Force
}

New-VM -Name $VmName `
    -Generation 1 `
    -MemoryStartupBytes $memoryStartupBytes `
    -VHDPath $usedVhdPath `
    -SwitchName $SwitchName | Out-Null

Set-VMProcessor -VMName $VmName -Count $CpuCount

Start-VM -Name $VmName | Out-Null

Write-Host "VM created: $VmName"
Write-Host "Connect with: vmconnect.exe localhost $VmName"
