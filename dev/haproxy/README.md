# HAProxy + CertKit Agent Dev Stack

This folder contains a local dev environment that runs HAProxy and the
CertKit agent inside a single container. It is intended to validate inventory
collection and certificate synchronization against a server.

Files
- `haproxy.docker-compose.yml`: Compose definition for the HAProxy + agent container.
- `Dockerfile`: Builds the image with HAProxy, Go, and the agent runner.
- `config.json`: Minimal agent config used by the container.
- `haproxy.cfg`: HAProxy config that references the SSL cert/key locations.
- `reload-haproxy.sh`: Rebuilds the HAProxy PEM and reloads the service.
- `run-certkit-agent.sh`: Build-and-run script invoked by the container startup.
- `start-services.sh`: Starts the agent in the background and runs HAProxy in the foreground.

Run
From this directory:

```bash
docker compose -f haproxy.docker-compose.yml up --build
```

Run local build explicitly:

```bash
CERTKIT_AGENT_SOURCE=local docker compose -f haproxy.docker-compose.yml up --build
```

Run published release:

```bash
CERTKIT_AGENT_SOURCE=release docker compose -f haproxy.docker-compose.yml up --build
```
