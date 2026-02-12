# CLI Reference

This is the canonical command reference for `certkit-agent`.

## Command Summary

```text
certkit-agent install    [--service-name NAME] [--config PATH] [--key REGISTRATION_KEY]
certkit-agent uninstall  [--service-name NAME] [--config PATH]
certkit-agent run        [--config PATH] [--once] [--key REGISTRATION_KEY]
certkit-agent register   REGISTRATION_KEY [--config PATH]
certkit-agent validate   [--config PATH]
certkit-agent version
```

## Defaults

- Service name default: `certkit-agent`
- Config path default (Linux): `/etc/certkit-agent/config.json`
- Config path default (Windows): `C:\ProgramData\CertKit\certkit-agent\config.json`

## Commands

### `install`

```text
certkit-agent install [--service-name NAME] [--config PATH] [--key REGISTRATION_KEY]
```

- Creates config if missing.
- Installs/updates service using the provided service name and config path.
- `--key` is used only when creating a new config.

Examples:

```bash
# Linux
sudo certkit-agent install
sudo certkit-agent install --service-name my-agent --config /opt/certkit/config.json --key rk_xxx
```

```powershell
# Windows (elevated)
certkit-agent.exe install
certkit-agent.exe install --service-name my-agent --config "C:\ProgramData\CertKit\my-agent\config.json" --key rk_xxx
```

### `uninstall`

```text
certkit-agent uninstall [--service-name NAME] [--config PATH]
```

- Removes service and agent files for the target installation.
- Attempts best-effort unregister call before cleanup.

Examples:

```bash
# Linux
sudo certkit-agent uninstall
sudo certkit-agent uninstall --service-name my-agent --config /opt/certkit/config.json
```

```powershell
# Windows (elevated)
certkit-agent.exe uninstall
certkit-agent.exe uninstall --service-name my-agent --config "C:\ProgramData\CertKit\my-agent\config.json"
```

### `run`

```text
certkit-agent run [--config PATH] [--once] [--key REGISTRATION_KEY]
```

- Runs the agent using the selected config path.
- `--once` performs one registration/poll/sync pass and exits.
- `--key` is used when creating a new config.

Examples:

```bash
certkit-agent run
certkit-agent run --once
certkit-agent run --config /etc/certkit-agent/config.json --key rk_xxx
```

### `register`

```text
certkit-agent register REGISTRATION_KEY [--config PATH]
```

- Requires positional registration key argument.
- Writes/updates key in config and registers the agent.

Examples:

```bash
certkit-agent register rk_xxx
certkit-agent register rk_xxx --config /etc/certkit-agent/config.json
```

### `validate`

```text
certkit-agent validate [--config PATH]
```

- Validates config, key material, reachability, and registration state.
- Exit code `0` on success, non-zero on failure.

Examples:

```bash
certkit-agent validate
certkit-agent validate --config /etc/certkit-agent/config.json
```

### `version`

```text
certkit-agent version
```

Prints the agent version.