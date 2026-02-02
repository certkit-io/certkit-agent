# How the CertKit Agent Works

This document explains the agent’s runtime behavior, architecture, and security model. The goal is to be transparent and explicit about what the agent does on your machines.

## Overview

The CertKit Agent is a small Go service that:
- Registers a host with CertKit.
- Polls for certificate configuration updates.
- Fetches certificates (PEM or PFX) and deploys them locally.
- Runs optional update commands to reload services.
- Reports inventory data back to CertKit.

The implementation attempts to be straightforward in an effort to make auditing easier.

## Lifecycle & Polling

1. **Startup**
   - The agent loads `config.json` and ensures a local keypair exists.
2. **Registration**
   - If no `agent_id` exists, the agent uses your bootstrap registration key to register with CertKit.
3. **Polling**
   - The agent polls for configuration updates on a 30‑second loop. (Coming soon: making this configurable)
   - Certificate sync runs every ~10 minutes (or immediately after config changes).  Synchronization is typically a no-op, but it does ensure that the expected certificates live in the expected locations (and match the expected thumbprints) every 10 minutes.
   - Inventory updates run every ~8 hours (or immediately after config changes).  That way if you add new software to your host we'll pick it up and make configuration easier in the UI.
4. **Synchronization**
   - If a certificate has changed, the agent fetches it and writes to the configured destination(s).
   - If an update command is configured, it is executed to reload the service.

## Platform Behavior

### Linux
- Certificates are written as PEM and key files to configured paths. (If you want JKS or other formats let us know)
- Update commands are executed via `sh -c`.
- Systemd is supported and is the default install mode.

### Windows
- The agent installs as a Windows service (LocalSystem by default).
- Logs are written to `C:\ProgramData\CertKit\certkit-agent\certkit-agent.log`.
- **IIS configurations** are handled via PFX: the agent imports the PFX into LocalMachine\My and updates IIS bindings.
- **Traditional PEM/key workflows** (Apache, nginx, etc.) are also supported on Windows.

## Security Model

### Keypair generation
- The agent generates an **Ed25519** keypair locally if one does not exist.
- The private key stays on the host (stored in `config.json`); only the public key is sent to the server.

### Request signing
- API requests are signed using the agent’s Ed25519 private key.
- The signature covers:
  - HTTP method
  - request path and query
  - host
  - timestamp
  - body SHA256
- Signed metadata is sent in headers (`Authorization`, `X-Agent-*`), enabling server‑side verification and replay protection.

### Transport security
- The agent uses HTTPS for API calls (default `https://app.certkit.io`).
- Registration keys are only used during initial registration.

### Least privilege & transparency
- The agent only performs actions described in this repository: write certs, reload services, and report inventory.
- It does **not** execute arbitrary commands unless you explicitly configure an update command.
- The code is fully public and intentionally designed to be clear, explicit, and auditable.

## Safety First
We do our best to make sure this code is easy to read and understand. The more eyes on it the better. We are making every effort to keep our security risk small.  That said, there can always be misses. If you have concerns or want to review specific behavior, open an issue or submit a PR—security feedback is always welcome.  Or you can email us at hello@certkit.io
