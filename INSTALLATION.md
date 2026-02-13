# Installation Guide

This document expands on the install notes in the README and focuses on practical, repeatable setups for Linux, Windows, and Docker sidecar deployments.
For command syntax and flags, see [CLI-REFERENCE.md](CLI-REFERENCE.md).

## Table of Contents
- [Linux](#linux)
  - [Systemd Service (Recommended)](#systemd-service-recommended)
  - [Linux Uninstall](#linux-uninstall)
  - [Docker Sidecar](#docker-sidecar)
    - [Mode 1: Socket exec (default)](#mode-1-socket-exec-default)
    - [Mode 2: Watch + reload](#mode-2-watch--reload)
    - [Mode 3: PID namespace](#mode-3-pid-namespace)
- [Windows](#windows)
  - [Windows Service Install](#windows-service-install)
  - [Windows Uninstall](#windows-uninstall)
  - [Logs](#logs)
  - [IIS vs PEM/Key Workflows](#iis-vs-pemkey-workflows)
  - [Apache on Windows](#apache-on-windows)
- [Need Help or Want Support for More Software?](#need-help-or-want-support-for-more-software)

## Linux

### Systemd Service (Recommended)

The Linux installer downloads the latest release, verifies the checksum, installs the binary, writes a systemd unit, and starts the service.

```bash
sudo env REGISTRATION_KEY="your.registration_key_here" \
bash -c 'curl -fsSL https://app.certkit.io/agent/latest/install.sh | bash'
```

Service management:

```bash
systemctl status certkit-agent
journalctl -u certkit-agent -f
```

If you don't use systemd, you can still run the agent directly:

```bash
./certkit-agent run --config /etc/certkit-agent/config.json
```

### Linux Uninstall

Uninstall removes the systemd unit, config file, and installed binary:

```bash
sudo certkit-agent uninstall
```

If you installed with custom values, pass the same options used at install time:

```bash
sudo certkit-agent uninstall --service-name my-agent --config /opt/certkit/config.json
```

### Docker Sidecar

The agent can run as a sidecar container, writing certificates into a shared volume that your web server container consumes.

Common setup:
- Shared volume mounted at `/certs` in both containers.
- CertKit destinations: `/certs/<name>.crt` and `/certs/<name>.key`.
- Reload mechanism depends on the mode (see below).

At a high level, the agent writes new files into `/certs`, and your web server
reloads them without rebuilding the container or restarting your service.

Choosing a reload mode:
- **Socket exec:** simplest and most reliable, but requires Docker socket access.
- **Watch + reload:** avoids the Docker socket and is safest, but needs a watcher.
- **PID namespace:** avoids the socket and is lightweight, but reduces isolation.

Below are complete, minimal compose examples you can adapt to your existing stack.
They assume a shared `certs` volume and an nginx container named `web`.

#### Mode 1: Socket exec (default)

**How it works:** the agent calls `docker exec` to reload the web server container.

**Security tradeoff:** mounting `/var/run/docker.sock` gives the agent root-level
control of the Docker host. Use in trusted environments only.

**Operational tradeoff:** very simple and reliable, no custom scripts in the web
server container.

**Setup essentials:**
- Mount the Docker socket into the agent container.
- Use an update command that runs `docker exec`.

**Compose example:**

```yaml
services:
  web:
    image: nginx:alpine
    container_name: web
    volumes:
      - ./certs:/certs
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "8443:443"

  certkit-agent:
    image: ghcr.io/certkit-io/certkit-agent:latest
    environment:
      REGISTRATION_KEY: YOUR_REGISTRATION_KEY
    volumes:
      - ./config:/etc/certkit-agent
      - ./certs:/certs
      - /var/run/docker.sock:/var/run/docker.sock
```

**CertKit update command:**

```
docker exec web nginx -s reload
```

#### Mode 2: Watch + reload

**How it works:** the web server container watches the shared cert directory and reloads itself.

**Security tradeoff:** safest option because the agent doesn't need the Docker
socket and can't control other containers.

**Operational tradeoff:** requires a file watcher and a custom entrypoint. If
the watcher dies, reloads stop until the container restarts.

**Setup essentials:**
- Enable a file watcher in the web server container.
- No update command needed.

**Compose example:**

```yaml
services:
  web:
    image: nginx:alpine
    container_name: web
    environment:
      WATCH_CERTS: "1"
    entrypoint: ["/bin/sh", "/usr/local/bin/nginx-start.sh"]
    volumes:
      - ./certs:/certs
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./nginx-start.sh:/usr/local/bin/nginx-start.sh:ro
    ports:
      - "8443:443"

  certkit-agent:
    image: ghcr.io/certkit-io/certkit-agent:latest
    environment:
      REGISTRATION_KEY: YOUR_REGISTRATION_KEY
    volumes:
      - ./config:/etc/certkit-agent
      - ./certs:/certs
```

**/nginx-start.sh:**

```bash
#!/usr/bin/env sh
set -euo pipefail

# Start watcher in background
while inotifywait -e close_write,create,delete,move /certs >/dev/null 2>&1; do
  nginx -s reload || true
done &

# Run nginx in foreground
exec nginx -g 'daemon off;'

```

**CertKit update command:** *(leave empty / no-op)*

#### Mode 3: PID namespace

**How it works:** the agent shares the web server's PID namespace and sends it a HUP.

**Security tradeoff:** more isolated than Docker socket, but less isolated than
separate PID namespaces (the agent can see and signal the web server process).

**Operational tradeoff:** no extra tooling, but you must ensure PID 1 in the web
container handles `HUP` correctly.

**Setup essentials:**
- Share PID namespace with the web server container.
- Use a simple signal command.

**Compose example:**

```yaml
services:
  web:
    image: nginx:alpine
    container_name: web
    volumes:
      - ./certs:/certs
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "8443:443"

  certkit-agent:
    image: ghcr.io/certkit-io/certkit-agent:latest
    pid: "service:web"
    environment:
      REGISTRATION_KEY: YOUR_REGISTRATION_KEY
    volumes:
      - ./config:/etc/certkit-agent
      - ./certs:/certs
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
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://app.certkit.io/agent/latest/install.ps1 | iex"
```

The installer also writes an Add/Remove Programs entry ("CertKit Agent") that
points to a local uninstall script at:

```
C:\Program Files\CertKit\bin\uninstall.ps1
```

### Windows Uninstall

ARP uninstall removes the service, config, `C:\ProgramData\CertKit`, and `C:\Program Files\CertKit`.

Preferred:
- Open **Settings -> Apps -> Installed apps**.
- Select **CertKit Agent** and click **Uninstall**.

PowerShell using the same ARP uninstall mechanism:

```powershell
$app = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $app.UninstallString -Verb RunAs -Wait
```

CLI fallback (elevated PowerShell):

```powershell
& "C:\Program Files\CertKit\bin\certkit-agent.exe" uninstall
# CLI fallback removes service + config + C:\ProgramData\CertKit.
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

If you want support for additional software, or you run into issues, please open an issue or submit a PR. We're customer-driven and happy to help.


