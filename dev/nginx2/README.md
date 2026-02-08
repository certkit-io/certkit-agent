# Nginx2 + CertKit Agent Dev Stack

This scenario matches `dev/nginx` but uses `sites-available` and
`sites-enabled` instead of `conf.d`.

Files
- `nginx2.docker-compose.yml`: Compose definition for the nginx + agent container.
- `Dockerfile`: Builds the image with nginx, Go, and the agent runner.
- `config.json`: Minimal agent config used by the container.
- `site-both.conf`: Copied to both `/etc/nginx/sites-available/` and `/etc/nginx/sites-enabled/`.
- `site-enabled-only.conf`: Present only in `/etc/nginx/sites-enabled/`.
- `site-available-only.conf`: Present only in `/etc/nginx/sites-available/`.
- `run-certkit-agent.sh`: Build-and-run script invoked by the container startup.
- `start-services.sh`: Starts the agent in the background and runs nginx in the foreground.

Run
From this directory:

```bash
docker compose -f nginx2.docker-compose.yml up --build
```

Run local build explicitly:

```bash
CERTKIT_AGENT_SOURCE=local docker compose -f nginx2.docker-compose.yml up --build
```

Run published release:

```bash
CERTKIT_AGENT_SOURCE=release docker compose -f nginx2.docker-compose.yml up --build
```
