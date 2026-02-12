# Cron + CertKit Agent Dev Stack

This stack runs a Linux container with `cron` and a prebuilt CertKit agent
binary copied from `dist/bin`.

Use this when you want to validate scheduled `run --run-once` behavior.

Files
- `cron.docker-compose.yml`: Compose definition for the cron container.
- `Dockerfile`: Image with cron, shell tools, and the Linux agent binary from `dist/bin`.
- `start-services.sh`: Starts cron and keeps the container alive.
- `setup-cron.sh`: Manually runs `register`, `validate`, and installs a cron schedule.

Prerequisite
Build artifacts first (from repo root):

```powershell
.\scripts\build.ps1
```

This creates `dist/bin/certkit-agent_linux_amd64` used by the Docker build.

Run
From this directory:

```bash
docker compose -f cron.docker-compose.yml up --build -d
```

Shell access

```bash
docker exec -it certkit-cron-dev bash
```

Setup cron job (manual)
Inside the container:

```bash
/opt/certkit-agent/setup-cron.sh
```

Or pass key explicitly:

```bash
/opt/certkit-agent/setup-cron.sh <REGISTRATION_KEY>
```

Environment variables
- `REGISTRATION_KEY`: Used by `setup-cron.sh` if no argument is passed.
- `CERTKIT_API_BASE`: Used when first creating config.
- `CERTKIT_CONFIG_PATH`: Optional config path override (default `/etc/certkit-agent/config.json`).
- `CERTKIT_CRON_SCHEDULE`: Optional cron schedule override (default `*/5 * * * *`).
- `CERTKIT_CRON_LOG`: Optional log path override (default `/var/log/certkit-agent/cron.log`).

Monitor

```bash
docker logs -f certkit-cron-dev
docker exec -it certkit-cron-dev cat /etc/cron.d/certkit-agent
docker exec -it certkit-cron-dev tail -f /var/log/certkit-agent/cron.log
docker exec -it certkit-cron-dev pgrep -a cron
```

Stop

```bash
docker compose -f dev/cron/cron.docker-compose.yml down
```
