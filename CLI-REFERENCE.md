# CLI Reference

## Name

`certkit-agent` - install, run, register, validate, and uninstall the CertKit Agent.

## Synopsis

```text
certkit-agent install    [--key REGISTRATION_KEY] [--service-name NAME] [--config PATH]
certkit-agent uninstall  [--service-name NAME] [--config PATH]
certkit-agent run        [--key REGISTRATION_KEY] [--config PATH] [--once]
certkit-agent register   REGISTRATION_KEY [--config PATH]
certkit-agent validate   [--config PATH]
certkit-agent version
```

## Defaults

- Service name: `certkit-agent`
- Default config path (Linux): `/etc/certkit-agent/config.json`
- Default config path (Windows): `C:\ProgramData\CertKit\certkit-agent\config.json`
- `--service-name` and `--config` are optional and primarily for advanced/non-default deployments.

## Command Reference

### `install`

#### Synopsis

```text
certkit-agent install [--key REGISTRATION_KEY] [--service-name NAME] [--config PATH]
```

#### Options

- `--key REGISTRATION_KEY`
  - Registration key used only when a new config must be created.
- `--service-name NAME`
  - Optional. Advanced setup for non-default service naming.
- `--config PATH`
  - Optional. Advanced setup for non-default config path.

#### Behavior

- Creates config if missing.
- Installs/updates service configuration for the selected service name and config path.
- Preserves existing config when already present.

#### Examples

```bash
# Linux default install
sudo certkit-agent install --key abc.xyz

# Linux custom service/config
sudo certkit-agent install --key abc.xyz --service-name edge-agent --config /opt/certkit/edge/config.json
```

```powershell
# Windows (elevated) default install
certkit-agent.exe install --key abc.xyz

# Windows (elevated) custom service/config
certkit-agent.exe install --key abc.xyz --service-name edge-agent --config "C:\ProgramData\CertKit\edge\config.json"
```

### `uninstall`

#### Synopsis

```text
certkit-agent uninstall [--service-name NAME] [--config PATH]
```

#### Options

- `--service-name NAME`
  - Optional. Advanced setup for non-default service naming.
- `--config PATH`
  - Optional. Advanced setup for non-default config path.

#### Behavior

- Removes service registration for the target install.
- Performs best-effort unregister call to CertKit.
- Removes installed agent files for the target install.

#### Examples

```bash
sudo certkit-agent uninstall
sudo certkit-agent uninstall --service-name edge-agent --config /opt/certkit/edge/config.json
```

```powershell
certkit-agent.exe uninstall
certkit-agent.exe uninstall --service-name edge-agent --config "C:\ProgramData\CertKit\edge\config.json"
```

### `run`

#### Synopsis

```text
certkit-agent run [--key REGISTRATION_KEY] [--config PATH] [--once]
```

#### Options

- `--key REGISTRATION_KEY`
  - Registration key used only if a new config must be created.
- `--config PATH`
  - Optional. Advanced setup for non-default config path.
- `--once`
  - Execute one poll and sync and exit.

#### Behavior

- Loads or initializes config.
- Registers on startup if registration is required.
- Performs poll/sync work loop (or one-shot when `--once` is set).

#### Examples

```bash
certkit-agent run
certkit-agent run --once
certkit-agent run --key abc.xyz --config /etc/certkit-agent/config.json
```

### `register`

#### Synopsis

```text
certkit-agent register REGISTRATION_KEY [--config PATH]
```

#### Arguments

- `REGISTRATION_KEY` (required, positional)

#### Options

- `--config PATH`
  - Optional. Advanced setup for non-default config path.

#### Behavior

- Writes/updates registration key in config.
- Registers the agent and persists agent credentials.

#### Examples

```bash
certkit-agent register abc.xyz
certkit-agent register abc.xyz --config /etc/certkit-agent/config.json
```

```powershell
certkit-agent.exe register abc.xyz
certkit-agent.exe register abc.xyz --config "C:\ProgramData\CertKit\certkit-agent\config.json"
```

### `validate`

#### Synopsis

```text
certkit-agent validate [--config PATH]
```

#### Options

- `--config PATH`
  - Optional. Advanced setup for non-default config path.

#### Behavior

- Validates config structure and required values.
- Reports registration/keypair state and connectivity checks.
- Returns non-zero exit code on validation failure.

#### Examples

```bash
certkit-agent validate
certkit-agent validate --config /etc/certkit-agent/config.json
```

```powershell
certkit-agent.exe validate
certkit-agent.exe validate --config "C:\ProgramData\CertKit\certkit-agent\config.json"
```

### `version`

#### Synopsis

```text
certkit-agent version
```

#### Behavior

- Prints the agent version string.

## Operational Sequences

### Install First, Register Later

```bash
sudo certkit-agent install --key abc.xyz --service-name edge-agent --config /opt/certkit/edge/config.json
sudo certkit-agent register abc.xyz --config /opt/certkit/edge/config.json
```

```powershell
certkit-agent.exe install --key abc.xyz --service-name edge-agent --config "C:\ProgramData\CertKit\edge\config.json"
certkit-agent.exe register abc.xyz --config "C:\ProgramData\CertKit\edge\config.json"
```

### Register First, Install Second

```bash
sudo certkit-agent register abc.xyz --config /opt/certkit/edge/config.json
sudo certkit-agent install --key abc.xyz --service-name edge-agent --config /opt/certkit/edge/config.json
```

```powershell
certkit-agent.exe register abc.xyz --config "C:\ProgramData\CertKit\edge\config.json"
certkit-agent.exe install --key abc.xyz --service-name edge-agent --config "C:\ProgramData\CertKit\edge\config.json"
```

### Cron (Linux, `run --once`)

```bash
# 1) Initialize config and register once
certkit-agent register abc.xyz --config /opt/certkit/cron/config.json
certkit-agent validate --config /opt/certkit/cron/config.json

# 2) Schedule recurring one-shot sync
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/certkit-agent run --once --config /opt/certkit/cron/config.json >> /var/log/certkit-agent-cron.log 2>&1") | crontab -
```

### Ad-Hoc Foreground (No Service Install)

```bash
# Register once (if not already registered)
certkit-agent register abc.xyz --config /tmp/certkit-agent/config.json

# Run daemon loop in the foreground
certkit-agent run --config /tmp/certkit-agent/config.json
```
