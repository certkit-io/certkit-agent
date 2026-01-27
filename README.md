# Certkit Agent (BETA, use with caution)

[![CI](https://github.com/certkit-io/certkit-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/certkit-io/certkit-agent/actions/workflows/ci.yml)  [![Release](https://github.com/certkit-io/certkit-agent/actions/workflows/release.yml/badge.svg)](https://github.com/certkit-io/certkit-agent/actions/workflows/release.yml)

The Certkit Agent runs directly on your hosts and manages the full certificate lifecycle from registration through renewal and deployment. Once installed, the agent securely connects to CertKit, installs the certificates your hosts are authorized for, and keeps everything continuously up to date.

## Prerequisites

- A [CertKit](https://app.certkit.io) account. You can register for a free trial [here](https://app.certkit.io).
- A **registration key** from your CertKit account (set via the `REGISTRATION_KEY` environment variable or in the config file)

## Install

The fastest way to install the agent is with the one-line installer script. This downloads the latest release, verifies its checksum, installs the binary, and sets up the systemd service:

```bash
sudo env REGISTRATION_KEY="your.registration_key_here" \
bash -c 'curl -fsSL https://raw.githubusercontent.com/certkit-io/certkit-agent/main/scripts/install.sh | bash'
```

Get the full install snippet from your [CertKit Account](https://app.certkit.io).

*Note:* If you do not have systemd, the agent install will still configure the agent, but you must manually configure the agent to autostart.

## Usage

The agent has two commands: `install` and `run`.

### `certkit-agent install`

Writes a systemd unit file and starts the service. Must be run as root.

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

## Configuration

The agent stores its configuration in JSON format (default: `/etc/certkit-agent/config.json`). A default config file is created automatically on install when one does not already exist.

*Configurations are unique*: A configuration is unique to an instance of the agent. Do not copy it wholesale when stamping out additional agents. To mass deploy the config file instead of running the install script, the config should have all sections removed besides the `bootstrap` section.

## Supported Platforms

- Linux
- Windows (Coming Soon!)
- Docker Sidecar (Coming Soon!)

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

## Feedback and Support

If you run into a bug, have a feature request, or have questions, please open an [issue](issues) or email us at [hello@certkit.io](mailto:hello@certkit.io).

## License

This software is released under the MIT license. See the [LICENSE](LICENSE) file for details.
