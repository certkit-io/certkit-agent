# Docker Sidecar (nginx + CertKit Agent)

This folder provides multiple Docker sidecar setups: an nginx container serves TLS
from a shared volume, and the CertKit agent runs in a separate container and
writes certificates into that same volume. You can choose how nginx is reloaded:

- **Socket exec**: agent runs `docker exec` (requires Docker socket).
- **Watch + reload**: nginx watches `/certs` and reloads itself.
- **PID namespace**: agent sends `HUP` to nginx PID 1 (shared PID namespace).

The default `-Mode` is `socket` when omitted.

## How it works
- Both containers share `./certs` (mounted at `/certs`).
- nginx serves `ssl_certificate /certs/nginx.crt` and `ssl_certificate_key /certs/nginx.key`.
- The agent fetches certificates and writes them into `/certs`.
- nginx is reloaded via `docker exec certkit-nginx nginx -s reload` (requires the Docker socket).

## Run (release)

```powershell
.\run-release.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY"  # default: socket
.\run-release.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY" -Mode socket
.\run-release.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY" -Mode watch
.\run-release.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY" -Mode pid
```

## Run (local build)

```powershell
.\build-and-run-local.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY"  # default: socket
.\build-and-run-local.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY" -Mode socket
.\build-and-run-local.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY" -Mode watch
.\build-and-run-local.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY" -Mode pid
```

## Configure CertKit

In your CertKit UI, set the certificate destinations to:

- PEM: `/certs/nginx.crt`
- Key: `/certs/nginx.key`
- Update command (socket exec): `docker exec certkit-nginx nginx -s reload`
- Update command (watch): *(leave empty / no-op)*
- Update command (pid namespace): `kill -HUP 1`

## Notes
- The socket-exec stack mounts `/var/run/docker.sock` to run `docker exec`. This is powerful; only use in trusted environments.
- nginx listens on port `443` in the container and is exposed as `9445` on the host.
- Stop script: `stop-container.ps1 -Mode socket|watch|pid`.
