# RRAS / SSTP Dev VM (Windows Server 2019/2022)

This stack uses a Windows Server VM because RRAS isn't supported in Windows
containers. The scripts below create a Hyper-V VM, install the Remote Access
role, and guide you through RRAS + SSTP setup.

Prereqs
- Windows 10 Pro/Enterprise with Hyper-V enabled
- Windows Server 2022 evaluation VHD

Download (Windows Server 2022 eval VHD)
```
https://go.microsoft.com/fwlink/p/?clcid=0x409&country=us&culture=en-us&linkid=2195166
```

Expected location
- `C:\Source\CertKitOther\certkit-agent\dev\rras\downloads\WindowsServer2022_Eval.vhd`

Quick start (host)
1) Create the VM from the downloaded VHD:

   .\New-RrasVmFromVhd.ps1

2) Connect and finish first-boot setup:

   vmconnect.exe localhost certkit-rras

3) Copy the dev\rras folder into the VM (PowerShell Direct):

   .\Copy-RrasScriptsToVm.ps1 -Password "YOUR_VM_ADMIN_PASSWORD"

4) Inside the VM, run:

   C:\dev\rras\Configure-Rras.ps1

5) Follow the printed RRAS wizard steps.

6) Validate:

   C:\dev\rras\Verify-Rras.ps1

Connectivity notes
- The VM uses the Hyper-V "Default Switch" by default; the host can reach the
  VM on the NAT IP assigned to the VM.
- The setup script creates a self-signed cert for rras.dev.local and exports
  it to C:\rras\certs\rras-dev.cer. Add a hosts entry on your host mapping
  rras.dev.local to the VM IP and import that cert into your host's Trusted
  Root store so SSTP connects cleanly.

Monitor (host)
- VM status:
  `Get-VM -Name certkit-rras | Format-Table Name, State, CPUUsage, MemoryAssigned`
- VM IP:
  `Get-VMNetworkAdapter -VMName certkit-rras | Select-Object -ExpandProperty IPAddresses`
- Console:
  `vmconnect.exe localhost certkit-rras`

Stop (host)
- Graceful stop:
  `Stop-VM -Name certkit-rras`
- Force power off:
  `Stop-VM -Name certkit-rras -TurnOff`

Troubleshooting
- If SSTP connections fail, confirm the RRAS service is running, port 443 is
  listening, and the SSL certificate binding is set in the RRAS UI.

Connect via VPN (SSTP)
1) On the host, add a hosts entry for the VM IP:
   `rras.dev.local   <VM_IP>`
2) Import `C:\rras\certs\rras-dev.cer` into the host "Trusted Root Certification Authorities".
3) Create a new VPN connection in Windows:
   - Server name: `rras.dev.local`
   - VPN type: SSTP
4) Use the VM's local user credentials to connect.
