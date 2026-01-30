# Apache (Windows) + CertKit Agent Dev Stack

This folder provides a Windows container dev stack that runs Apache HTTPD and the
CertKit agent inside a single Windows container. It is intended to validate
inventory collection and IIS/Apache sync behavior on Windows.

## Requirements
- Docker Desktop **switched to Windows containers**.
- Hyper-V isolation is used (set in compose) so Server container images can run on Windows 10/11 hosts.
- Admin PowerShell on the host is recommended when building/running Windows containers.

## Files
- `Dockerfile`: Windows Server Core base image + Apache + OpenSSL + startup script.
- `start-services.ps1`: Installs the agent and starts Apache in the foreground.
- `apache-windows.docker-compose.yml`: Compose definition for the Apache + agent container.
- `apache-windows.local.docker-compose.yml`: Compose override to mount a local Windows binary.
- `build.ps1`: Builds the local Windows agent binary.
- `build-and-run-local.ps1`: Builds and runs with a local agent binary.
- `run-release.ps1`: Runs using the latest (or specified) release binary.
- `stop-container.ps1`: Stops and removes the container.

## Run (release binaries)
From repo root:

```powershell
$env:CERTKIT_API_BASE="YOUR_API_BASE"
$env:REGISTRATION_KEY="YOUR_REGISTRATION_KEY"
$env:CERTKIT_AGENT_SOURCE="release"
$env:CERTKIT_WINDOWS_BASE_IMAGE="mcr.microsoft.com/windows/servercore:ltsc2019"
# Optional: override Apache Lounge ZIP URL
# $env:CERTKIT_APACHE_ZIP_URL="https://www.apachelounge.com/download/VC17/binaries/httpd-2.4.58-win64-VS17.zip"

docker compose -f dev\apache-windows\apache-windows.docker-compose.yml up --build
```

## Run (local binary)
From `dev\apache-windows`:

```powershell
.\build-and-run-local.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY"
```

## Run (release, one step)
From `dev\apache-windows`:

```powershell
.\run-release.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY"
.\run-release.ps1 -ApiBase "YOUR_API_BASE" -RegistrationKey "YOUR_REGISTRATION_KEY" -Version "v1.2.3"
```

## Notes
- Apache is installed from Apache Lounge ZIP in the Dockerfile. Override `CERTKIT_APACHE_ZIP_URL` if you need a different build/version.
- OpenSSL is installed via Chocolatey to generate a self-signed dev certificate.
- The default config path in this stack is `C:\dev\apache-windows\config.json`, which is bind-mounted to `dev\apache-windows\config.json` on the host.
- The HTTPS endpoint is exposed on host port `9444`.
