# Certkit Agent

[![CI](https://github.com/certkit-io/certkit-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/certkit-io/certkit-agent/actions/workflows/ci.yml) [![Release](https://github.com/certkit-io/certkit-agent/actions/workflows/release.yml/badge.svg)](https://github.com/certkit-io/certkit-agent/actions/workflows/release.yml)

`certkit-agent` runs on your host, registers with CertKit, polls for assigned certificate configuration, deploys certificates, runs optional reload commands, and reports inventory.

## Documentation

- [INSTALLATION.md](INSTALLATION.md) - install and deployment procedures (Linux, Windows, Docker sidecar)
- [CLI-REFERENCE.md](CLI-REFERENCE.md) - command/flag reference and operational sequences
- [HOW-IT-WORKS.md](HOW-IT-WORKS.md) - architecture and security model

## Prerequisites

- CertKit account: [app.certkit.io](https://app.certkit.io)
- Registration key from your CertKit app (format similar to `abc.xyz`)

## Quick Start

### Linux (systemd)

```bash
sudo env REGISTRATION_KEY="abc.xyz" \
bash -c 'curl -fsSL https://app.certkit.io/agent/latest/install.sh | bash'
```

### Windows (elevated PowerShell)

```powershell
$env:REGISTRATION_KEY="abc.xyz"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr -useb https://app.certkit.io/agent/latest/install.ps1 | iex"
```

### Docker

```bash
docker run --rm \
  -e REGISTRATION_KEY="abc.xyz" \
  -v ./certkit-agent:/etc/certkit-agent \
  ghcr.io/certkit-io/certkit-agent:latest
```

For sidecar patterns and reload-mode tradeoffs, see [INSTALLATION.md](INSTALLATION.md).

## CLI At A Glance

```text
certkit-agent install    [--key REGISTRATION_KEY] [--service-name NAME] [--config PATH]
certkit-agent uninstall  [--service-name NAME] [--config PATH]
certkit-agent run        [--key REGISTRATION_KEY] [--config PATH] [--once]
certkit-agent register   REGISTRATION_KEY [--config PATH]
certkit-agent validate   [--config PATH]
certkit-agent version
```

Common commands:

```bash
# one-time registration + service install
sudo certkit-agent install --key abc.xyz

# foreground daemon mode
certkit-agent run

# one-shot poll/sync (for cron or ad-hoc checks)
certkit-agent run --once

# config and connectivity checks
certkit-agent validate
```

Windows uninstall is typically done via Add/Remove Programs (`CertKit Agent`). CLI fallback is:

```powershell
& "C:\Program Files\CertKit\bin\certkit-agent.exe" uninstall
```

## Configuration

Default config path:
- Linux: `/etc/certkit-agent/config.json`
- Windows: `C:\ProgramData\CertKit\certkit-agent\config.json`

A new config is created automatically if missing. Configs are agent-instance specific; do not clone a full config between hosts.

## Platform Support

- Linux
- Windows
- Docker sidecar

Auto-discovery support:
- Linux: Apache, Nginx, HAProxy, LiteSpeed
- Windows: IIS, RRAS

## Logs

- Linux systemd: `journalctl -u certkit-agent -f`
- Linux foreground run: stdout/stderr
- Windows service: `C:\ProgramData\CertKit\certkit-agent\certkit-agent.log`

## Troubleshooting

- Validate config and connectivity: `certkit-agent validate`
- Verify service state: `systemctl status certkit-agent` or `Get-Service certkit-agent`
- Confirm API reachability and firewall rules to your configured CertKit API base URL

## Support

- Issues: [GitHub Issues](https://github.com/certkit-io/certkit-agent/issues)
- Email: [hello@certkit.io](mailto:hello@certkit.io)

## License

MIT. See [LICENSE](LICENSE).
