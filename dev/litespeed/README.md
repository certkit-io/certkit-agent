# LiteSpeed + CertKit Agent Dev Stack

This folder contains a local dev environment that runs OpenLiteSpeed and the
CertKit agent inside a single container. It is intended to validate inventory
collection and certificate synchronization against a server.

Files
- `litespeed.docker-compose.yml`: Compose definition for the LiteSpeed + agent container.
- `Dockerfile`: Builds the image with OpenLiteSpeed and the agent binary.
- `config.json`: Minimal agent config used by the container.
- `vhconf.conf`: OpenLiteSpeed vhost config with SSL cert/key paths.
- `run-certkit-agent.sh`: Runs the agent with the local config.
- `start-services.sh`: Starts LiteSpeed and runs the agent in the background.

Run
From this directory:

```bash
docker compose -f litespeed.docker-compose.yml up --build
```

Run local build explicitly:

```bash
CERTKIT_AGENT_SOURCE=local docker compose -f litespeed.docker-compose.yml up --build
```

Run published release:

```bash
CERTKIT_AGENT_SOURCE=release docker compose -f litespeed.docker-compose.yml up --build
```
