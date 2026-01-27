# Apache + CertKit Agent Dev Stack

This folder contains a local dev environment that runs apache and the CertKit
agent inside a single container. It is intended to validate inventory
collection and certificate synchronization against a server.

Files
- `apache.docker-compose.yml`: Compose definition for the apache + agent container.
- `Dockerfile`: Builds the image with apache, Go, and the agent runner.
- `config.json`: Minimal agent config used by the container.
- `certkit.conf`: Apache site config that references the SSL cert/key locations.
- `run-certkit-agent.sh`: Build-and-run script invoked by the container startup.
- `start-services.sh`: Starts the agent in the background and runs apache in the foreground.

Run
From this directory:

```bash
docker compose -f apache.docker-compose.yml up --build
```

Run local build explicitly:

```bash
CERTKIT_AGENT_SOURCE=local docker compose -f apache.docker-compose.yml up --build
```

Run published release:

```bash
CERTKIT_AGENT_SOURCE=release docker compose -f apache.docker-compose.yml up --build
```
