# Legacy Windows build (Server 2008 R2 / 2012 R2)

Go 1.21 (Aug 2023) dropped support for Windows 7, 8, 8.1, Server 2008 R2, Server 2012 and
Server 2012 R2 — i.e. every Windows with an internal version below 10.0. Binaries built with
Go 1.21+ die during runtime init on those hosts with:

```
Exception 0xc0000005 0x8 0x0 0x0
PC=0x0
runtime.asmstdcall(0x400)
```

(the runtime calls a Win32 procedure that `GetProcAddress` could not resolve). Nothing in our
code runs before the crash, so it cannot be worked around in the agent.

This folder builds a separate **legacy** Windows binary with **Go 1.20.14**, the last release
that supports those OSes. Everything legacy-specific lives here; the main `go.mod` and the
Go 1.24 toolchain are untouched.

## How it works

| File | Purpose |
|---|---|
| `go.legacy.mod` / `go.legacy.sum` | Module file for the legacy build: `go 1.20`, `x/sys v0.15.0`, `x/crypto v0.17.0` — the last versions of those modules whose `go` directive is ≤ 1.20. |
| `build.ps1` / `build.sh` | Build `dist/bin/certkit-agent_windows_amd64_legacy.exe` using `go1.20.14 build -modfile=legacy/go.legacy.mod`. |

The trick is Go's `-modfile` flag: it tells the `go` command to use an alternate module file
for a single invocation, against the **same source tree**. The file is deliberately *not*
named `go.mod`, so the main toolchain never sees it as a nested-module boundary and
`go build ./...`, `go test ./...`, `go mod tidy` at the root behave exactly as before.

The legacy toolchain is installed side-by-side and does not replace `go`:

```
go install golang.org/dl/go1.20.14@latest
go1.20.14 download          # ~110 MB, installs to ~/sdk/go1.20.14
```

## Building

```powershell
.\legacy\build.ps1           # -> dist\bin\certkit-agent_windows_amd64_legacy.exe
```

```sh
./legacy/build.sh
```

The version string gets a `+legacy` build-metadata suffix (e.g. `v1.13.0+legacy`) so the
variant is visible in `certkit-agent version`, logs and the `X-Agent-Version` header, without
changing its semver precedence.

Updating the dependency pins:

```
go1.20.14 mod tidy -modfile=legacy/go.legacy.mod
```

## Installing on a legacy host

`install.ps1` refuses to run on Windows < 10.0 and the release pipeline does not yet publish
the legacy asset, so the binary is installed by hand. Customer-facing steps (test run and
full service install) are in [`legacy_install_instructions.md`](legacy_install_instructions.md).

## Constraints — read before shipping this to a customer

1. **Self-update will brick a legacy agent.** Self-update downloads whatever `DownloadURL`
   the server sends. The server currently only knows `GOOS`/`GOARCH`, so it would push the
   Go 1.24 binary, which crashes on start. Before a legacy agent is left unattended, the
   server must recognise the variant (the `+legacy` version suffix, or a dedicated header)
   and either send the legacy asset or never send an update.
2. **Go 1.20 is end-of-life** (last security patch: Feb 2024). Go binaries carry their own
   TLS/crypto stack, so stdlib CVEs fixed after that date apply to this build. The same goes
   for the pinned `x/crypto` / `x/sys`.
3. **Keep the main tree 1.20-compatible.** The CI job `legacy-build` compiles the tree with
   Go 1.20.14 and the legacy modfile on every PR. If it fails, someone used a Go ≥ 1.21
   language feature (`min`/`max`/`clear`, `for range N`, range-over-func, generic type
   aliases, …) or stdlib package/API (`slices`, `maps`, `cmp`, `log/slog`, `iter`,
   `math/rand/v2`, `sync.OnceFunc`, `context.WithoutCancel`, …). Replace it with a small
   helper — see `containsString` in `agent/agent.go` for the precedent.
4. **Runtime behaviour on old hosts is untested.** It compiles and the test suite passes
   under Go 1.20, but the cert-store / IIS / RDP / Exchange code paths call Win32 APIs via
   `x/sys` lazy loading; an API missing on 2008 R2 surfaces as an error at call time.
   Exercise each deployment target on a real legacy host before relying on it.
5. The legacy OSes themselves are out of Microsoft support (2008 R2: Jan 2020, 2012 R2:
   Oct 2023). Running a certificate agent on them is the customer's risk to accept.
