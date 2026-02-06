# Systemd + Nginx + CertKit Agent Dev Stack

This scenario runs `systemd` as PID 1 in the container, and runs both `nginx`
and `certkit-agent` as systemd services.

The agent is built from local source inside the container at startup (like `dev/nginx`).

Files
- `systemd.docker-compose.yml`: Compose definition for the systemd container.
- `Dockerfile`: Image with Go, systemd, and nginx.
- `bootstrap-certkit-agent.sh`: Builds local source and runs `certkit-agent install`.
- `certkit-agent-bootstrap.service`: One-shot systemd unit that installs/updates the agent on boot.
- `nginx-certkit.conf`: Nginx TLS vhost served by nginx systemd service.
- `.env`: Local environment values.
- `config.json`: Agent config path used by install/run.

Run
1. Start the stack:
```bash
docker compose -f systemd.docker-compose.yml up --build
```

Monitor
```bash
docker exec -it certkit-systemd-dev systemctl status certkit-agent --no-pager
docker exec -it certkit-systemd-dev systemctl status nginx --no-pager
docker exec -it certkit-systemd-dev journalctl -u certkit-agent -f
docker exec -it certkit-systemd-dev journalctl -u nginx -f
```

Quick checks
```bash
curl -k https://localhost:9447/
docker exec -it certkit-systemd-dev systemctl is-active certkit-agent nginx
```

Stop
```bash
docker compose -f dev/systemd/systemd.docker-compose.yml down
```

Notes
- Use `CERTKIT_AGENT_SOURCE=local` (default) to build from local source.
- Use `CERTKIT_AGENT_SOURCE=release` to install from the published install script.
- The bootstrap unit runs at container boot and re-installs/updates the service each time.
