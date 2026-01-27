# Standalone CertKit Agent Dev Stack

This folder contains a local dev environment that runs just the CertKit
agent inside a single container. It is intended to validate that the agent
can register and fetch certificates from the server.

Files
- `docker-compose.yml`: Compose definition for the agent container.
- `config.json`: Generated at runtime (ignored by git).
- `.env`: Local-only environment values for the container (ignored by git).

Example `.env` (placeholders):

```
CERTKIT_API_BASE=YOUR_API_BASE
REGISTRATION_KEY=YOUR_REGISTRATION_KEY
CERTKIT_AGENT_SOURCE=local
```

Run
From this directory:

```bash
docker compose -f docker-compose.yml up --build
```

Run all webserver stacks (PowerShell):

```powershell
.\run-all.ps1        # local build
.\run-all.ps1 -Release
```
