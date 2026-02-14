# Installation Guide

This document describes supported installation and deployment patterns for `certkit-agent` on Linux, Windows, and Docker.

For full command syntax and flags, see [CLI-REFERENCE.md](CLI-REFERENCE.md).

## Table of Contents
- [Linux](#linux)
  - [Systemd Install (Recommended)](#systemd-install-recommended)
  - [CLI Install Patterns](#cli-install-patterns)
  - [Verification](#verification)
  - [Uninstall](#uninstall)
- [Windows](#windows)
  - [Service Install (Recommended)](#service-install-recommended)
  - [CLI Install Patterns](#cli-install-patterns-1)
  - [Verification](#verification-1)
  - [Uninstall](#uninstall-1)
- [Docker Sidecar](#docker-sidecar)
  - [Mode 1: Socket Exec](#mode-1-socket-exec)
  - [Mode 2: Watch and Reload](#mode-2-watch-and-reload)
  - [Mode 3: PID Namespace](#mode-3-pid-namespace)
- [Support](#support)

## Linux

### Systemd Install (Recommended)

Use the hosted installer to download the latest release, verify checksum, install the binary, create/update the systemd service, and start it.

```bash
sudo env REGISTRATION_KEY="your.registration_key_here" \
bash -c 'curl -fsSL https://app.certkit.io/agent/latest/install.sh | bash'
```

Default paths and service name:
- Service: `certkit-agent`
- Config: `/etc/certkit-agent/config.json`

### CLI Install Patterns

Use these patterns when you manage the binary yourself.

Install with defaults:

```bash
sudo certkit-agent install --key YOUR_REGISTRATION_KEY
```

Install with custom service name and config path:

```bash
sudo certkit-agent install \
  --service-name edge-agent \
  --config /opt/certkit/edge-agent/config.json \
  --key YOUR_REGISTRATION_KEY
```

Install first, register later:

```bash
sudo certkit-agent install --service-name edge-agent --config /opt/certkit/edge-agent/config.json
sudo certkit-agent register YOUR_REGISTRATION_KEY --config /opt/certkit/edge-agent/config.json
```

Register first, install second:

```bash
sudo certkit-agent register YOUR_REGISTRATION_KEY --config /opt/certkit/edge-agent/config.json
sudo certkit-agent install --service-name edge-agent --config /opt/certkit/edge-agent/config.json
```

Run directly without systemd:

```bash
certkit-agent run --config /etc/certkit-agent/config.json
```

### Verification

```bash
systemctl status certkit-agent
journalctl -u certkit-agent -f
certkit-agent validate --config /etc/certkit-agent/config.json
```

### Uninstall

Remove service registration, agent files, and config for the target install:

```bash
sudo certkit-agent uninstall
```

If installed with non-default values, pass matching flags:

```bash
sudo certkit-agent uninstall --service-name edge-agent --config /opt/certkit/edge-agent/config.json
```


## Windows

### Service Install (Recommended)

Run from an elevated PowerShell session.

```powershell
$env:REGISTRATION_KEY="your.registration_key_here"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://app.certkit.io/agent/latest/install.ps1 | iex"
```

Default paths and service name:
- Service: `certkit-agent`
- Binary: `C:\Program Files\CertKit\bin\certkit-agent.exe`
- Config: `C:\ProgramData\CertKit\certkit-agent\config.json`
- Log file: `C:\ProgramData\CertKit\certkit-agent\certkit-agent.log`

The installer also registers an Add/Remove Programs entry (`CertKit Agent`).

### CLI Install Patterns

Use these patterns when managing install/update directly.

Install with defaults:

```powershell
certkit-agent.exe install --key YOUR_REGISTRATION_KEY
```

Install with custom service name and config path:

```powershell
certkit-agent.exe install --service-name edge-agent --config "C:\ProgramData\CertKit\edge-agent\config.json" --key YOUR_REGISTRATION_KEY
```

Install first, register later:

```powershell
certkit-agent.exe install --service-name edge-agent --config "C:\ProgramData\CertKit\edge-agent\config.json"
certkit-agent.exe register YOUR_REGISTRATION_KEY --config "C:\ProgramData\CertKit\edge-agent\config.json"
```

Register first, install second:

```powershell
certkit-agent.exe register YOUR_REGISTRATION_KEY --config "C:\ProgramData\CertKit\edge-agent\config.json"
certkit-agent.exe install --service-name edge-agent --config "C:\ProgramData\CertKit\edge-agent\config.json"
```

### Verification

```powershell
Get-Service certkit-agent
Get-Content "C:\ProgramData\CertKit\certkit-agent\certkit-agent.log" -Tail 200
certkit-agent.exe validate --config "C:\ProgramData\CertKit\certkit-agent\config.json"
```

### Uninstall

Preferred: use Add/Remove Programs (`Settings -> Apps -> Installed apps -> CertKit Agent -> Uninstall`).

PowerShell via ARP uninstall string:

```powershell
$app = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $app.UninstallString -Verb RunAs -Wait
```

CLI fallback:

```powershell
& "C:\Program Files\CertKit\bin\certkit-agent.exe" uninstall
```

## Docker Sidecar

Use the public image:
- `ghcr.io/certkit-io/certkit-agent:latest`

Sidecar assumptions:
- Agent and web server share a cert volume (for example `/certs`).
- Cert destinations point into that shared volume.
- Reload behavior depends on selected mode.

Reference implementation:
- `dev/docker-sidecar`

### Mode 1: Socket Exec

Mechanism:
- Agent uses Docker socket and runs `docker exec <web> <reload-command>`.

Requirements:
- Mount `/var/run/docker.sock` into the agent container.

Security profile:
- Highest operational access (socket grants broad Docker host control).

Operational profile:
- Simplest integration; no custom watcher required.

Example update command:

```text
docker exec web nginx -s reload
```

### Mode 2: Watch and Reload

Mechanism:
- Web container watches cert files and reloads itself on change.

Requirements:
- File watcher in web container.
- Agent update command can be empty.

Security profile:
- No Docker socket required.

Operational profile:
- Requires maintaining watcher logic in web image/entrypoint.

### Mode 3: PID Namespace

Mechanism:
- Agent shares PID namespace with web container and sends a signal.

Requirements:
- Configure shared PID namespace in compose.

Security profile:
- More isolated than Docker socket; less isolated than separate PID namespaces.

Operational profile:
- Lightweight; requires web PID 1 to handle `HUP` correctly.

Example update command:

```text
kill -HUP 1
```

## Support

For additional software support or deployment issues, open an issue or submit a PR.
