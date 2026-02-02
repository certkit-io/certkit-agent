# Installation Guide

This document expands on the install notes in the README and focuses on practical, repeatable setups for Linux, Windows, and Docker sidecar deployments.

## Table of Contents
- [Linux](#linux)
  - [Systemd Service (Recommended)](#systemd-service-recommended)
  - [Docker Sidecar](#docker-sidecar)
    - [Mode 1: Socket exec (default)](#mode-1-socket-exec-default)
    - [Mode 2: Watch + reload](#mode-2-watch--reload)
    - [Mode 3: PID namespace](#mode-3-pid-namespace)
- [Windows](#windows)
  - [Windows Service Install](#windows-service-install)
  - [Logs](#logs)
  - [IIS vs PEM/Key Workflows](#iis-vs-pemkey-workflows)
  - [Apache on Windows](#apache-on-windows)
- [Need Help or Want Support for More Software?](#need-help-or-want-support-for-more-software)

## Linux

### Systemd Service (Recommended)

The Linux installer downloads the latest release, verifies the checksum, installs the binary, writes a systemd unit, and starts the service.

```bash
sudo env REGISTRATION_KEY="your.registration_key_here" \
bash -c 'curl -fsSL https://raw.githubusercontent.com/certkit-io/certkit-agent/main/scripts/install.sh | bash'
```

Service management:

```bash
systemctl status certkit-agent
journalctl -u certkit-agent -f
```

If you don’t use systemd, you can still run the agent directly:

```bash
./certkit-agent run --config /etc/certkit-agent/config.json
```

### Docker Sidecar

The agent can run as a sidecar container, writing certificates into a shared volume that your web server container consumes.

Common setup:
- Shared volume mounted at `/certs` in both containers.
- CertKit destinations: `/certs/<name>.crt` and `/certs/<name>.key`.
- Reload mechanism depends on the mode (see below).

#### Mode 1: Socket exec (default)

**How it works:** the agent calls `docker exec` to reload the web server container.

**Setup essentials:**
- Mount the Docker socket into the agent container.
- Use an update command that runs `docker exec`.

```yaml
services:
  certkit-agent:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

**CertKit update command:**

```
docker exec <nginx_container> nginx -s reload
```

#### Mode 2: Watch + reload

**How it works:** the web server container watches the shared cert directory and reloads itself.

**Setup essentials:**
- Enable a file watcher in the web server container.
- No update command needed.

```yaml
services:
  nginx:
    environment:
      WATCH_CERTS: "1"
```

**Minimal watcher script (example):**

```bash
#!/usr/bin/env sh
set -euo pipefail

while inotifywait -e close_write,create,delete,move /certs >/dev/null 2>&1; do
  nginx -s reload || true
done
```

**CertKit update command:** *(leave empty / no-op)*

#### Mode 3: PID namespace

**How it works:** the agent shares the web server’s PID namespace and sends it a HUP.

**Setup essentials:**
- Share PID namespace with the web server container.
- Use a simple signal command.

```yaml
services:
  certkit-agent:
    pid: "service:nginx"
```

**CertKit update command:**

```
kill -HUP 1
```

## Windows

### Windows Service Install

Run from an elevated PowerShell prompt. The installer downloads the latest release, verifies it, installs the service, and starts the agent:

```powershell
$env:REGISTRATION_KEY="your.registration_key_here"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://raw.githubusercontent.com/certkit-io/certkit-agent/main/scripts/install.ps1 | iex"
```

### Logs

The Windows service writes logs to:

```
C:\ProgramData\CertKit\certkit-agent\certkit-agent.log
```

### IIS vs PEM/Key Workflows

- **IIS** uses the Windows certificate store and IIS bindings. For IIS configurations, the agent fetches a PFX and installs it into LocalMachine\My, then applies it to the IIS binding.
- **Traditional servers** (nginx/apache/haproxy) use PEM and key files on disk; the agent writes those files and runs your update command.

### Apache on Windows

Apache on Windows is supported for inventory discovery and PEM/key workflows. See `dev/apache-windows` for a working container example.

## Need Help or Want Support for More Software?

If you want support for additional software, or you run into issues, please open an issue or submit a PR. We’re customer‑driven and happy to help.
