# Certkit Agent

[![CI](https://github.com/certkit-io/certkit-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/certkit-io/certkit-agent/actions/workflows/ci.yml)  [![Release](https://github.com/certkit-io/certkit-agent/actions/workflows/release.yml/badge.svg)](https://github.com/certkit-io/certkit-agent/actions/workflows/release.yml)

The Certkit Agent runs directly on your hosts and manages the full certificate lifecycle from registration through renewal and deployment. Once installed, the agent securely connects to CertKit, installs the certificates your hosts are authorized for, and keeps everything continuously up to date.

See `HOW-IT-WORKS.md` for a deeper dive into architecture and security.

## Prerequisites

- A **[CertKit](https://app.certkit.io) account**. You can sign-up for a free trial [here](https://app.certkit.io/signup).
- A **registration key** from your CertKit account (set via the `REGISTRATION_KEY` environment variable or in the config file)

## Install

The fastest way to install the agent is with the one-line installer script. This downloads the latest release, verifies its checksum, installs the binary, and sets up the systemd service. For more detailed examples, see `INSTALLATION.md`.

```bash
sudo env REGISTRATION_KEY="your.registration_key_here" \
bash -c 'curl -fsSL https://app.certkit.io/agent/latest/install.sh | bash'
```

Get the full install snippet from your [CertKit Account](https://app.certkit.io).

*Note:* If you do not have systemd, the agent install will still configure the agent, but you must manually configure the agent to autostart.

### Windows (PowerShell)

Run from an elevated PowerShell prompt. This downloads the latest release, verifies it, installs the service, and starts the agent:
See [INSTALLATION.md](INSTALLATION.md) for more Windows details.

```powershell
$env:REGISTRATION_KEY="your.registration_key_here"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://app.certkit.io/agent/latest/install.ps1 | iex"
```

### Docker Image

The agent is published as a container image in GHCR. Example:

```bash
docker run --rm \
  -e REGISTRATION_KEY="your.registration_key_here" \
  -v ./certkit-agent:/etc/certkit-agent \
  ghcr.io/certkit-io/certkit-agent:latest
```

```yaml
# docker-compose.yml
services:
  certkit-agent:
    image: ghcr.io/certkit-io/certkit-agent:latest
    environment:
      REGISTRATION_KEY: your.registration_key_here
    volumes:
      - ./certkit-agent:/etc/certkit-agent
```

The Docker image is typically used as a **sidecar** that writes certificates to a shared volume. See the Docker Sidecar section in `INSTALLATION.md` for full examples.

## Update

Simply re-run the install snippets above to update an existing Certkit Agent installation. This is supported in both Linux and Windows.

## Usage

The agent has three commands: `install`, `uninstall`, and `run`.

### `certkit-agent install`

Writes an initial bootstrap configuration, a systemd unit file and starts the service. Must be run as root.

```
certkit-agent install [--service-name NAME] [--unit-dir DIR] [--bin-path PATH] [--config PATH]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--service-name` | `certkit-agent` | systemd service name |
| `--unit-dir` | `/etc/systemd/system` | systemd unit directory |
| `--bin-path` | *(current executable)* | path to the certkit-agent binary |
| `--config` | `/etc/certkit-agent/config.json` | path to the config file |

**Examples:**

```bash
# Default install
sudo ./certkit-agent install

# Custom service name and config path
sudo ./certkit-agent install --service-name my-agent --config /opt/certkit/config.json

# Check status after install
systemctl status certkit-agent
```

### `certkit-agent run`

Starts the agent daemon. This is what the systemd service calls, you can also run it directly for debugging or on systems without systemd support.

```
certkit-agent run [--config PATH]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `/etc/certkit-agent/config.json` | path to the config file |

**Examples:**

```bash
# Run with default config
./certkit-agent run

# Run with a custom config path
./certkit-agent run --config /etc/certkit-agent/config.json
```

### `certkit-agent uninstall`

Removes the agent service registration, config, and installed binary.

Linux:
```
certkit-agent uninstall [--service-name NAME] [--unit-dir DIR] [--config PATH]
```

Windows:
```
certkit-agent.exe uninstall [--service-name NAME] [--config PATH]
```

Examples:
```bash
# Linux uninstall (service + config)
sudo ./certkit-agent uninstall
```

```powershell
# Windows uninstall (service + config)
.\certkit-agent.exe uninstall
```

## Configuration

The agent stores its configuration in JSON format (default: `/etc/certkit-agent/config.json`). A default config file is created automatically on install when one does not already exist.

*Configurations are unique*: A configuration is unique to an instance of the agent. Do not copy it wholesale when stamping out additional agents. To mass deploy the config file instead of running the install script, the config should have all sections removed besides the `bootstrap` section.

### Minimal config example

```json
{
  "api_base": "https://app.certkit.io",
  "bootstrap": {
    "registration_key": "YOUR_REGISTRATION_KEY"
  },
  "certificate_configurations": []
}
```

## Supported Platforms

- Linux
- Windows
- Docker Sidecar

## Autodetection Support
The agent attempts to autodetect common software. The agent can manage certificates for any software, but manual configuration is needed when the software is not auto-detected.

On *Linux* the agent currently auto-detects:

- Apache
- Nginx
- HAProxy
- LiteSpeed

**Need something else?** We're very customer request driven, make an [issue](issues) or email us at [hello@certkit.io](mailto:hello@certkit.io)

## How It Works
The agent is intended to run continually as a service in the background (using the `certkit-agent run` command). When running, the agent does a few different things:

1. **Registration**

   On first run, the agent registers itself with your CertKit account using your registration key and generates an RSA keypair for secure authentication.
2. **Configuration polling**

   The agent periodically polls CertKit for certificate configurations assigned to it.
3. **Certificate synchronization**

   Certificates are fetched, verified, and written to the paths you configure in the CertKit UI (e.g., `/etc/ssl/certs/`).
4. **Deployment**

   After writing certificates, the agent can execute update commands (e.g., `systemctl reload nginx`) to apply them without downtime.
5. **Inventory reporting**

   The agent periodically reports its host inventory back to CertKit so you have visibility into what is deployed where.

## Docker Sidecar

The agent can run as a sidecar container and write certificates into a shared volume
that your web server container consumes. A ready-to-run example is in `dev/docker-sidecar`.
For more detailed setup, see `INSTALLATION.md`.

Key points:
- Mount a shared volume for certs (e.g., `/certs`).
- Configure CertKit to write PEM/key into that volume.
- Use an update command to reload the main container (e.g., `docker exec certkit-nginx nginx -s reload`), or use a watch/`pid`-namespace approach.
- The socket-exec approach requires access to the Docker socket.

### Sidecar Modes

**1) Socket exec (default)**
- Setup: mount `/var/run/docker.sock` into the agent container.
- CertKit update command: `docker exec <nginx_container> nginx -s reload`.
- Best for: dev or trusted environments.
  Security: grants root-level control of the Docker host via the socket.
  Ops: simplest and most reliable, no custom web container scripts.

```yaml
# agent container
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

**2) Watch + reload**
- Setup: nginx container watches `/certs` and reloads itself on changes.
- CertKit update command: *(leave empty / no-op)*.
- Best for: avoiding Docker socket while keeping automatic reloads.
  See `dev/docker-sidecar/nginx-start.sh` for a minimal watcher example.
  Security: safest option (no Docker socket).
  Ops: requires a watcher and a custom entrypoint; watcher failures stop reloads.

```yaml
# nginx container
environment:
  WATCH_CERTS: "1"
```

**3) PID namespace**
- Setup: run agent container with `pid: "service:nginx"` to share PID namespace.
- CertKit update command: `kill -HUP 1`.
- Best for: socket-less reload with minimal extra tooling.
  Security: more isolated than Docker socket, less isolated than separate PID namespaces.
  Ops: no watcher, but relies on PID 1 handling `HUP` correctly.

```yaml
# agent container
pid: "service:nginx"
```

## Logs

- **Linux (systemd):** `journalctl -u certkit-agent -f`
- **Linux (manual run):** stdout/stderr of the process
- **Windows (service):** `C:\ProgramData\CertKit\certkit-agent\certkit-agent.log`

## Uninstall / Cleanup

### Linux

`uninstall` removes the systemd unit, config, and installed binary path.

```bash
sudo certkit-agent uninstall
# If you used a custom service/unit/config path, pass the same flags used during install.
# Example:
sudo certkit-agent uninstall --service-name my-agent --unit-dir /etc/systemd/system --config /opt/certkit/config.json
```

### Windows (PowerShell, elevated)

ARP uninstall removes the service, config, `C:\ProgramData\CertKit`, and `C:\Program Files\CertKit`.

```powershell
# Preferred: Settings -> Apps -> Installed apps -> CertKit Agent -> Uninstall
# PowerShell using the same ARP uninstall mechanism:
$app = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent"
Start-Process -FilePath "cmd.exe" -ArgumentList "/c", $app.UninstallString -Verb RunAs -Wait

# CLI fallback:
& "C:\Program Files\CertKit\bin\certkit-agent.exe" uninstall
# CLI fallback removes service + config + C:\ProgramData\CertKit.
```

## Troubleshooting 

- **Service installed but not running:** check logs (see above) and verify the config path exists.
- **Cannot reach API:** verify network access and firewall rules.
- **Windows service has no output:** check `C:\ProgramData\CertKit\certkit-agent\certkit-agent.log`.

## Security Notes

- The agent stores its config and keys locally; keep the config file and `C:\ProgramData\CertKit` restricted to administrators.
- The agent runs as root (Linux) or LocalSystem (Windows) for certificate store access.

## Feedback and Support

If you run into a bug, have a feature request, or have questions, please open an [issue](issues) or email us at [hello@certkit.io](mailto:hello@certkit.io).

## License

This software is released under the MIT license. See the [LICENSE](LICENSE) file for details.
