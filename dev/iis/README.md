# IIS + CertKit Agent (Windows containers)

This folder provides a Windows container dev stack to validate **Windows service** install/run for the agent alongside IIS.

## Requirements
- Docker Desktop **switched to Windows containers**.
- Hyper-V isolation is used (set in compose) so Server container images can run on Windows 10/11 hosts.
- Admin PowerShell on the host is recommended when building/running Windows containers.

## Files
- `Dockerfile`: Windows IIS base image + startup script.
- `start-services.ps1`: Installs the agent as a Windows service and starts IIS.
- `iis.docker-compose.yml`: Compose definition for the IIS + agent container.
- `iis.local.docker-compose.yml`: Compose override to mount a local Windows binary.

## Run (release binaries)
From repo root:

```powershell
$env:CERTKIT_API_BASE="YOUR_API_BASE"
$env:REGISTRATION_KEY="YOUR_REGISTRATION_KEY"
$env:CERTKIT_AGENT_SOURCE="release"
$env:CERTKIT_WINDOWS_BASE_IMAGE="mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019"

docker compose -f dev\iis\iis.docker-compose.yml up --build
```

## Run (local binary)
Build a Windows binary and mount it into the container:

```powershell
# Build the Windows binary
.\scripts\build.sh  # or build manually with GOOS=windows GOARCH=amd64

$env:CERTKIT_API_BASE="YOUR_API_BASE"
$env:REGISTRATION_KEY="YOUR_REGISTRATION_KEY"
# Optional: override base image to match your host build
# $env:CERTKIT_WINDOWS_BASE_IMAGE="mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022"
# Optional: override default mount location
# $env:CERTKIT_AGENT_BINARY="C:\\opt\\certkit-agent\\certkit-agent_windows_amd64.exe"

docker compose -f dev\iis\iis.docker-compose.yml -f dev\iis\iis.local.docker-compose.yml up --build
```

## Build and run (one step)
From `dev\iis`:

```powershell
.\build-and-run.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY"
```

If you see a Windows image/host version mismatch, `build-and-run.ps1` sets `COMPOSE_COMPATIBILITY=1` so Docker honors `isolation: hyperv`.

`build-and-run.ps1` defaults `CERTKIT_WINDOWS_BASE_IMAGE` to `mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019`.

## Notes
- The container installs the service as **LocalSystem** for LocalMachine cert store access.
- This is a dev-only setup; Windows service behavior inside containers is not a 1:1 match with a full VM/host.
- If you need a fuller Windows environment, use a Windows VM and run the agent installer there.
- You can override the base image by setting `CERTKIT_WINDOWS_BASE_IMAGE` in your environment.

