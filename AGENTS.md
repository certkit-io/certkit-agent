# CertKit Agent Codebase Guide

This repository contains the CertKit Agent, a small daemon that registers a host with CertKit, polls for certificate configuration, fetches certificates, deploys them to the local system, and reports inventory.

The goal is a codebase that is approachable and reliable. **Simple, procedural, explicit code is always better than clever, abstract, or implicit code.** Prefer straightforward control flow, clear names, and minimal magic.

## High-Level Flow

1. **Startup & config load**
   - `cmd/certkit-agent/main.go` (and OS-specific entrypoints) parse CLI args and call `run`.
   - `config.LoadConfig` reads the JSON config and ensures key material exists.
2. **Registration**
   - `agent.NeedsRegistration` decides if registration is required.
   - `api.RegisterAgent` registers and stores the agent ID.
3. **Polling & sync**
   - `api.PollForConfiguration` returns certificate config updates.
   - `agent.SynchronizeCertificates` fetches new certs and writes them to the configured destinations.
4. **Deployment**
   - `runUpdateCommand` executes a command to reload/restart services after cert updates.
5. **Inventory**
   - `inventory.Collect` discovers local software + certificate locations.
   - `api.UpdateInventory` reports inventory to the server.

## Repository Layout

- `cmd/certkit-agent/`
  - CLI entrypoints (`main.go`) and OS-specific implementations (`main_windows.go`, `main_linux.go`).
  - `run_common.go` holds shared run loop logic.
- `agent/`
  - Core orchestration (registration, polling, synchronization, inventory).
  - `synchronize*.go` implements certificate sync paths; Windows IIS logic lives in `synchronize_iis_windows.go`.
- `api/`
  - HTTP client calls for registration, config polling, fetching certificates/PFX, inventory, and error reporting.
- `config/`
  - Config schema and persistence; `config.json` is the durable state for the agent.
- `inventory/`
  - Auto-discovery of web servers and certificate locations (Nginx, Apache, HAProxy, LiteSpeed, IIS).
  - Windows-specific providers/paths are included where needed.
- `crypto/`
  - Keypair creation and helpers.
- `utils/`
  - Small helpers: file IO, cert hashing, Windows machine ID, PowerShell runner (Windows-only), etc.
- `scripts/`
  - Install scripts used by releases (Linux `install.sh`, Windows `install.ps1`).
- `dev/`
  - Local dev stacks for validating behavior in containers (Linux and Windows).

## Platform Notes

- **Windows**
  - Uses `main_windows.go` for service installation and service execution.
  - IIS synchronization uses Windows certificate store and `IIS:\SslBindings` via PowerShell.
  - PowerShell execution is centralized in `utils/powershell_windows.go`.
- **Linux**
  - Uses systemd installer in `main_linux.go` and `scripts/install.sh`.
  - Inventory and sync paths use filesystem PEM locations.

## Style & Contribution Guidelines

- Prefer **simple, procedural, explicit** logic.
- Avoid abstraction layers that hide behavior or introduce implicit control flow.
- Keep functions small but not over-factored.
- Use clear error messages that describe the operation that failed.
- When adding OS-specific behavior, isolate it cleanly and keep the logic obvious.

## Adding New Inventory Providers

1. Add a new provider type that satisfies `inventory.Provider`.
2. Add it to the provider list in `inventory.getProviders`.
3. Keep parsing logic tolerant of partial/invalid configs; log and continue.

