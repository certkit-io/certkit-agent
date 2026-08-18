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
   - Certificate synchronization is run every time a new certificate is issued, the configuration changes, or the agent is restarted.  Synchronization will ensure that the certificates on disk match the certificates in the CertKit application.
   - On initial registration and subsequent agent restarts, we also compile a list of installed software that is running on the host that might require TLS/SSL certificates, making configuration simpler.
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

## Internal Host Monitoring

Hosts marked as internal in CertKit can be assigned to a specific agent, which then monitors their TLS certificates from inside your network — hosts the CertKit cloud cannot reach.

- **What the agent does:** for each assigned monitor it opens a single TCP connection to the configured `host:port` and performs a TLS handshake (2.5 second timeout). No request data is ever sent on the connection; the agent only captures the certificate the server presents.
- **How often:** every 8 hours, immediately when a monitor is first assigned or its name/port is edited, and on demand when you click Check Now in the CertKit UI.
- **What leaves your network:** certificate metadata only — the validity window (not-before/expiry), issuer DN, SHA-1 and SHA-256 fingerprints, serial number, a pass/fail reason, whether the chain's root is trusted in this host's OS trust store, and the certificate chain the server presented (public certificates only — sent with each result, not stored by CertKit).
- **How trust is judged:** the certificate chain is verified against the agent host's OS trust store. An internal host serving a private-CA certificate shows green on agents that trust that root, and "untrusted root" on hosts that don't.
- **Docker:** an agent running in a container monitors from the container's network namespace and uses the container's trust store, not the Docker host's.

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

### Locking an Agent
- You can lock an agent once you have the configuration set up and working the way you want.  
- This prevents unexpected changes to update commands by other users, and ensures configurations keep working.
- Locking is a single button push in the CertKit UI
- Once locked, the agent will no longer accept configuration updates from the application.  It will still update certifcates as they renew, but users in the UI will be unable to add, edit, or remove configurations from the agent.
- Unlocking an agent can **only** occur from the host.  Either by running `unlock` or removing the lock file.
- See [CLI-REFERENCE.md](./CLI-REFERENCE.md#lock) for more information.

### Least privilege & transparency
- The agent only performs actions described in this repository: write certs, reload services, and report inventory.
- It does **not** execute arbitrary commands unless you explicitly configure an update command.
- The code is fully public and intentionally designed to be clear, explicit, and auditable.

## Safety First
We do our best to make sure this code is easy to read and understand. The more eyes on it the better. We are making every effort to keep our security risk small.  That said, there can always be misses. If you have concerns or want to review specific behavior, open an issue or submit a PR—security feedback is always welcome.  Or you can email us at hello@certkit.io
