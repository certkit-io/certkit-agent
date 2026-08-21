# CertKit Agent — legacy Windows install (Server 2008 R2 / 2012 R2)

Everything runs from an **elevated (Administrator) PowerShell prompt**. Replace `<KEY>` with the
registration key from the CertKit app.

## 1. Stage the binary

```powershell
New-Item -ItemType Directory -Force "C:\Program Files\CertKit\bin" | Out-Null
Copy-Item .\certkit-agent_windows_amd64_legacy.exe "C:\Program Files\CertKit\bin\certkit-agent.exe"
& "C:\Program Files\CertKit\bin\certkit-agent.exe" version
```

`version` should print something like `certkit-agent v1.x.y+legacy ... go: go1.20.14`. 

## 2a. Test only — run once in the foreground

Registers the agent, does a single poll/sync cycle, logs to the console and exits. No service
is installed.

```powershell
& "C:\Program Files\CertKit\bin\certkit-agent.exe" run --once --key <KEY>
```

Then authorize the agent in the CertKit app under **Agents** and run the same command again
to see it pick up its configuration. Run it as many times as you like.

To clean up after a test:

```powershell
Remove-Item -Recurse -Force "C:\ProgramData\CertKit"
Remove-Item -Recurse -Force "C:\Program Files\CertKit"
```

## 2b. Full install — run as a Windows service

Creates the config (if missing), registers the `certkit-agent` service (LocalSystem, automatic
start, restart on failure) and starts it.

```powershell
& "C:\Program Files\CertKit\bin\certkit-agent.exe" install --key <KEY>
Get-Service certkit-agent
```

Authorize the agent in the CertKit app under **Agents**. From then on it polls on its own.

Useful paths:

- Config: `C:\ProgramData\CertKit\certkit-agent\config.json`
- Log: `C:\ProgramData\CertKit\certkit-agent\certkit-agent.log` (also Windows Event Log, source `CertKit`)

If you already did 2a, skip `--key` — the config from the test run is reused.

### Uninstall

```powershell
& "C:\Program Files\CertKit\bin\certkit-agent.exe" uninstall
Remove-Item -Recurse -Force "C:\ProgramData\CertKit"
Remove-Item -Recurse -Force "C:\Program Files\CertKit"
```

