# MSI-PLAN: Signed MSI Installer for certkit-agent

This document is the plan for shipping a code-signed MSI installer for the Windows agent,
built by GitHub Actions on every release, alongside (not replacing) the existing raw binary
build. It also covers the parts we were unsure about: what code signing actually involves in
2025+, what it does and does not buy us against antivirus/SmartScreen, and how the MSI must
coexist with the things the agent already does (self-registers its service, self-updates its
own exe, wipes its data on uninstall).

**Decisions already made** (treat as settled; rationale inline):

| Decision | Choice |
|---|---|
| Signing provider | Compare options (§2), pick after checking Azure Trusted Signing eligibility |
| Uninstall data policy | Keep current behavior: wipe `config.json` + `C:\ProgramData\CertKit` on uninstall; upgrades always preserve them |
| Self-update | Keep the exe-swap self-update; accept version drift in Add/Remove Programs; disable MSI "repair" |
| Binary release | Continues unchanged — and gets signed too, since AV scrutinizes it as much as the MSI |

**Implementation status** (Phases 1–3 are implemented in this repo; the MSI builds locally):

| Item | Status |
|---|---|
| Exe branding (`winres/`, build scripts) | ✅ Done — verified: exe carries icon + CompanyName/ProductName/FileVersion |
| `bootstrap-config` / `msi-cleanup` subcommands | ✅ Done — builds on windows and linux |
| WiX authoring (`packaging/windows/Package.wxs`) | ✅ Done — MSI builds with WiX **6.0.2** (see the WiX v7 note in §4) |
| Release workflow (build → package-windows → release) | ✅ Done — signing steps present but disabled behind `ENABLE_CODE_SIGNING` |
| `install.ps1` v2 (MSI + migration + `-Binary`) | ✅ Done — **not yet deployed to app.certkit.io** (cutover only after the first MSI-bearing release, §8) |
| UpgradeCode | ✅ Frozen: `6050598C-625B-461F-B8C8-989E2962E79D` — never change it |
| Logo assets | ✅ Done — real CertKit logo (rendered from the brand SVG) in `assets/certkit.{ico,png}` and `packaging/windows/{banner,dialog}.bmp`; to refresh art later, regenerate the same filenames/dimensions |
| Code signing | ✅ Done — Azure **Artifact Signing** (Trusted Signing was renamed Jan 2026) wired in `release.yml` via `azure/artifact-signing-action@v2`, OIDC federated credential scoped to the GitHub `release` environment; gated on repo variable `ENABLE_CODE_SIGNING` |
| VM install/upgrade/migration test matrix (§10 P2/P5) | ⏳ Not run yet — CI smoke-tests install/uninstall on the runner, but the migration and upgrade paths need a real VM pass |

---

## 1. Goals — why an MSI

- **AV/SmartScreen posture.** A signed MSI from a validated publisher is the least-suspicious
  possible delivery vehicle. Raw unsigned Go exes downloaded from the internet are the classic
  heuristic target (see §2.4).
- **Enterprise expectations.** Customers deploying agents fleet-wide expect an MSI they can push
  via GPO/Intune/SCCM (`msiexec /i certkit-agent.msi /qn REGISTRATIONKEY=...`).
- **Standard uninstall.** Windows Installer gives us a first-class Add/Remove Programs entry,
  transactional install/rollback, and clean upgrade semantics — replacing today's hand-written
  registry entry and embedded `uninstall.ps1`.
- **Branding.** Product icon in Add/Remove Programs, branded installer UI, and a proper
  VERSIONINFO resource on the exe itself.

The raw `certkit-agent_windows_amd64.exe` release asset keeps shipping: it stays the fallback
install path, the Linux-style manual option, and the payload for the agent's self-update.

## 2. Code signing

### 2.1 The landscape changed in 2023

Since June 2023, CA/Browser Forum rules require code-signing private keys (including plain OV
certificates) to live in FIPS-certified hardware — an HSM or a CA-operated cloud service. **You
can no longer buy a `.pfx` file and stick it in a GitHub secret.** Every practical CI signing
setup is now "the key lives in someone's cloud HSM and CI asks it to sign."

### 2.2 Provider comparison (decision pending)

| | **Azure Trusted Signing** | **SSL.com eSigner** | **DigiCert KeyLocker** |
|---|---|---|---|
| Cost | ~$9.99/mo (Basic tier) | ~$300–500/yr cert + per-signature or subscription fees | ~$500–700/yr cert + cloud key fees |
| Key storage | Microsoft-managed HSM | SSL.com cloud HSM | DigiCert cloud HSM |
| GitHub Actions | First-class: `azure/trusted-signing-action`, OIDC federated credential — **no stored secrets at all** | CodeSignTool CLI, credentials in repo secrets | smctl/signtool with KSP, credentials in repo secrets |
| Identity shown | CertKit legal entity | CertKit legal entity | CertKit legal entity |
| Eligibility catch | Org needs **3+ years of verifiable business history**, or falls back to individual validation (publisher shows the individual's name). Verify current terms at onboarding. | Standard OV validation, no company-age requirement | Standard OV validation, no company-age requirement |
| Cert lifetime quirk | Short-lived certs rotated continuously by Microsoft (fine — timestamping makes signatures permanent) | 1–3 yr cert | 1–3 yr cert |

**Recommendation:** Azure Trusted Signing if the CertKit entity passes eligibility — it is by far
the cheapest and the cleanest CI integration (OIDC, nothing to leak). If eligibility fails,
SSL.com eSigner is the pragmatic runner-up. Check eligibility **now** (Phase 0): identity
validation has a multi-day lead time and gates only the signing phase, nothing else.

> **Jan 2026 rename:** Microsoft renamed Trusted Signing to **Azure Artifact Signing**. The
> GitHub Action is now `azure/artifact-signing-action@v2` (input `signing-account-name`), and
> the IAM role is "Artifact Signing Certificate Profile Signer". Endpoints and behavior are
> unchanged. This is the provider we onboarded with.

Ruled out: **SignPath.io's free open-source tier** — this repo is Elastic License 2.0, which is
not OSI-approved, and their OSS program would show "SignPath Foundation" as publisher instead of
CertKit anyway. An EV certificate is also not worth chasing: Microsoft removed EV's instant
SmartScreen reputation (~2024), so EV now costs more for no practical benefit over OV/Trusted
Signing.

### 2.3 Signing mechanics

Order matters — inner artifacts before outer:

1. Build `certkit-agent_windows_amd64.exe` → **sign the exe**.
2. Build the MSI embedding the signed exe → **sign the MSI**.
3. Generate `certkit-agent_SHA256SUMS.txt` **after** signing (signing changes the bytes; today's
   workflow generates checksums at build time, which would break `install.ps1` verification on
   every release — see §7).

Requirements for every signature: SHA-256 file digest, and an **RFC 3161 timestamp** from the
provider's timestamp server. Timestamping is what keeps signatures valid after the certificate
expires or rotates — never skip it.

### 2.4 Honest expectations: what signing does and doesn't do

This is the part vendors don't tell you:

- **Signing ≠ instantly clean.** SmartScreen reputation accrues *per certificate* based on
  download volume and time without incidents. A brand-new cert still shows "unrecognized app"
  warnings for the first weeks/hundreds of downloads. It fades; it is not instant. Keep the same
  cert/publisher identity across releases so reputation compounds instead of resetting.
- **What signing does do immediately:** removes the "Unknown publisher" UAC prompt (shows
  "CertKit" instead), stops the most aggressive "unsigned PE downloaded from the internet"
  heuristics, and gives AV vendors an accountable identity — which drastically lowers
  false-positive rates and gives us standing to dispute them.
- **False positives still happen. Dispute them:**
  - Microsoft: submit via the WDSI portal (<https://www.microsoft.com/en-us/wdsi/filesubmission>)
    as a software developer. This is also worth doing *proactively* with each release's binaries
    to seed Defender's clean-file telemetry.
  - Other vendors (CrowdStrike, SentinelOne, Sophos, ESET…) each have FP-dispute portals; handle
    them as customers report.
- **Hygiene that keeps heuristics quiet:**
  - Real VERSIONINFO metadata on the exe (CompanyName, ProductName, FileDescription, version) —
    metadata-less stripped Go binaries pattern-match to malware (§3).
  - Never pack/compress the exe (no UPX). Our current `-s -w -trimpath` flags are fine.
  - Stable install paths, service name, and publisher string across releases.
  - Delivering via MSI is itself heuristically friendlier than a bare exe download.
- **Optional early-warning:** a CI step that submits the signed exe+MSI hashes to VirusTotal
  after release and fails loudly if engines flag them — we find out before customers do.

## 3. Exe branding: icon + version resource (`.syso`)

Go binaries carry Windows resources via `.syso` object files linked automatically by the Go
toolchain. Use [`go-winres`](https://github.com/tc-hib/go-winres) (invoked via `go run`, no
committed binaries, no CGO):

- **New committed files:** `winres/winres.json` (resource config) and `assets/certkit.ico`
  (multi-resolution: 16/24/32/48/64/256 — needs the CertKit logo, see Open Questions).
- **Generated at build time, gitignored:** `cmd/certkit-agent/rsrc_windows_amd64.syso`.
- Resource contents:
  - Icon (shows in Explorer, Task Manager, and via `ARPPRODUCTICON` in Add/Remove Programs).
  - VERSIONINFO: `CompanyName=CertKit`, `ProductName=CertKit Agent`,
    `FileDescription=CertKit Agent`, `FileVersion`/`ProductVersion` injected from the tag.
  - Manifest: `requestedExecutionLevel=asInvoker` (the exe is a service host and CLI — it must
    not UAC-prompt on every invocation; admin checks stay in code), `supportedOS` Win10/11.
- Build wiring, in **both** `scripts/build.sh` and `scripts/build.ps1`, before the Windows build:

  ```sh
  go run github.com/tc-hib/go-winres@v0.3.3 make \
    --in winres/winres.json --arch amd64 \
    --product-version "$VER_NUMERIC" --file-version "$VER_NUMERIC" \
    --out cmd/certkit-agent/rsrc
  ```

  The `_windows_amd64.syso` suffix means Linux builds are unaffected. Add `*.syso` to
  `.gitignore`. While touching `build.ps1`, fix the existing bug on line 43 where
  `-X main.version=v1.13.0` is hardcoded and ignores the `$Version` parameter.

Beyond looks, the version resource matters mechanically: Windows Installer file costing follows
"a versioned file always replaces an unversioned file," which makes the MSI overwriting a legacy
script-installed (unversioned) exe deterministic.

## 4. MSI architecture

Tooling: **WiX, pinned to v6.0.2** (`dotnet tool install --global wix --version 6.0.2`, plus
`WixToolset.Util.wixext/6.0.2` and `WixToolset.UI.wixext/6.0.2`). **Do not float to latest:**
WiX v7 refuses to run until the Open Source Maintenance Fee (OSMF) EULA is accepted
(error WIX7015), which would gate CI. Staying on v6 avoids that; if CertKit later wants v7
features, evaluate the OSMF terms first. Authoring lives in `packaging/windows/`:
`Package.wxs`, `license.rtf` (WixUI needs RTF; generate from `LICENSE`), branded
`banner.bmp` (493×58) and `dialog.bmp` (493×312).

### 4.1 Package skeleton

```xml
<Package Name="CertKit Agent" Manufacturer="CertKit"
         Version="$(var.Version)" UpgradeCode="6050598C-625B-461F-B8C8-989E2962E79D"
         Scope="perMachine" Compressed="yes">          <!-- built with -arch x64 -->

  <MajorUpgrade Schedule="afterInstallValidate"
      DowngradeErrorMessage="A newer version of CertKit Agent is already installed."/>
  <MediaTemplate EmbedCab="yes"/>

  <Icon Id="CertKitIcon" SourceFile="assets\certkit.ico"/>
  <Property Id="ARPPRODUCTICON" Value="CertKitIcon"/>
  <Property Id="ARPHELPLINK" Value="https://certkit.io"/>
  <Property Id="ARPNOMODIFY" Value="1"/>
  <Property Id="ARPNOREPAIR" Value="1"/>   <!-- repair would clobber a self-updated exe (§6) -->
  <Property Id="REGISTRATIONKEY" Hidden="yes" Secure="yes"/>

  <StandardDirectory Id="ProgramFiles64Folder">
    <Directory Id="CERTKITDIR" Name="CertKit">
      <Directory Id="BINDIR" Name="bin"/>   <!-- matches the legacy script layout exactly -->
    </Directory>
  </StandardDirectory>
  ...
</Package>
```

- **`UpgradeCode` is forever.** It is frozen as `6050598C-625B-461F-B8C8-989E2962E79D` — never
  change it; it is how future MSIs find and upgrade past installs. Component GUIDs use WiX
  auto-GUIDs (stable as long as install paths are stable).
- **`Version`** must be numeric `a.b.c`. Release tags are `vX.Y.Z` (stable) or
  `vX.Y.Z-<suffix>` (prerelease/testing, e.g. `v1.14.0-msi-alpha`); the workflow strips the
  suffix for ProductVersion and publishes suffixed tags as **GitHub prereleases**, so the
  `latest` release routes (and install.ps1) keep serving the last stable. Because a prerelease
  and its final share a ProductVersion, `MajorUpgrade` sets `AllowSameVersionUpgrades="yes"` —
  the final upgrades the prerelease in place (caveat: any same-version MSI replaces any other).
  Anything else — in particular `git describe` output like `1.11.0-3-gabc123` — still fails the
  build loudly rather than becoming a garbage ProductVersion.

### 4.2 Service, event source, cleanup of legacy litter

```xml
<Component Id="AgentExe" Directory="BINDIR">
  <File Id="AgentExeFile" Source="$(var.AgentExe)" Name="certkit-agent.exe" KeyPath="yes"/>

  <ServiceInstall Id="AgentService" Name="certkit-agent" DisplayName="CertKit Agent"
      Description="CertKit Agent service" Type="ownProcess" Start="auto"
      Account="LocalSystem" ErrorControl="normal"
      Arguments="run --service --service-name certkit-agent --config &quot;[CommonAppDataFolder]CertKit\certkit-agent\config.json&quot;">
    <util:ServiceConfig FirstFailureActionType="restart" SecondFailureActionType="restart"
        ThirdFailureActionType="restart" RestartServiceDelayInSeconds="5"
        ResetPeriodInDays="1"/>   <!-- replicates configureRecovery() in install/windows.go -->
  </ServiceInstall>
  <!-- Stop/remove block (Wait=yes) so upgrades can replace the exe; start
       does not (Wait=no) - the agent exits when it cannot register, and a
       failed first start must not roll back the install. install.ps1
       verifies the service is Running after install, as it always has. -->
  <ServiceControl Id="AgentServiceStopRemove" Name="certkit-agent"
      Stop="both" Remove="uninstall" Wait="yes"/>
  <ServiceControl Id="AgentServiceStart" Name="certkit-agent"
      Start="install" Wait="no"/>

  <!-- self-update litter + legacy script-install remnants -->
  <RemoveFile Id="RmOldExe" Name="certkit-agent.old.exe" On="both"/>
  <RemoveFile Id="RmNewExe" Name="certkit-agent.new.exe" On="both"/>
  <RemoveFile Id="RmLegacyUninstall" Name="uninstall.ps1" On="install"/>
</Component>

<Component Id="EventLogSource" Directory="BINDIR">
  <util:EventSource Log="Application" Name="CertKit"
      EventMessageFile="[System64Folder]EventCreate.exe"
      SupportsErrors="yes" SupportsWarnings="yes" SupportsInformationals="yes"
      KeyPath="yes"/>
</Component>

<!-- belt-and-suspenders: remove the legacy hand-written ARP key even on direct MSI installs -->
<Component Id="LegacyArpCleanup" Directory="BINDIR">
  <RemoveRegistryKey Root="HKLM" Action="removeOnInstall"
      Key="SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent"/>
</Component>
```

The MSI natively owns everything the script + `certkit-agent install` do today: service
creation with recovery policy, event-source registration, the Add/Remove Programs entry (now
automatic, branded, and correctly versioned), and file placement. The Go `install`/`uninstall`
commands remain untouched for Linux and the fallback path.

### 4.3 Custom actions — exactly two, no PowerShell

Installer-spawned PowerShell is an AV heuristic red flag and fragile besides. The only two
custom actions invoke **our own installed, signed exe** via `WixQuietExec64` (util extension),
both `Execute="deferred" Impersonate="no"` with the SetProperty/CustomActionData pattern.
Deferred CAs cannot read installer properties and do **not** inherit the invoking user's
environment — this is why today's `$env:REGISTRATION_KEY` passthrough cannot work inside an MSI
and the key must travel as a property.

```xml
<SetProperty Id="BootstrapConfig" Sequence="execute" Before="BootstrapConfig"
    Value="&quot;[BINDIR]certkit-agent.exe&quot; bootstrap-config --service-name certkit-agent --config &quot;[CommonAppDataFolder]CertKit\certkit-agent\config.json&quot; --key &quot;[REGISTRATIONKEY]&quot;"/>
<CustomAction Id="BootstrapConfig" DllEntry="WixQuietExec64" BinaryRef="Wix4UtilCA_X64"
    Execute="deferred" Impersonate="no" Return="check"/>

<SetProperty Id="MsiCleanup" Sequence="execute" Before="MsiCleanup"
    Value="&quot;[BINDIR]certkit-agent.exe&quot; msi-cleanup --config &quot;[CommonAppDataFolder]CertKit\certkit-agent\config.json&quot;"/>
<CustomAction Id="MsiCleanup" DllEntry="WixQuietExec64" BinaryRef="Wix4UtilCA_X64"
    Execute="deferred" Impersonate="no" Return="ignore"/>  <!-- best-effort; never block uninstall -->

<InstallExecuteSequence>
  <!-- files+service exist; runs BEFORE StartServices so first start finds a config -->
  <Custom Action="BootstrapConfig" After="InstallServices"
          Condition="NOT Installed OR REINSTALL"/>
  <!-- true uninstall only; exe must still exist → after StopServices, before RemoveFiles -->
  <Custom Action="MsiCleanup" After="StopServices"
          Condition="(REMOVE~=&quot;ALL&quot;) AND (NOT UPGRADINGPRODUCTCODE)"/>
</InstallExecuteSequence>
```

- Effective install order: `InstallFiles → InstallServices → BootstrapConfig → StartServices`.
  Uninstall order: `StopServices → MsiCleanup → DeleteServices → RemoveFiles`.
- **`NOT UPGRADINGPRODUCTCODE` is the load-bearing condition**: during a MajorUpgrade the old
  product's uninstall runs with that property set, so `MsiCleanup` is skipped and the agent's
  config, keypair, and identity survive upgrades. On a true uninstall it runs and wipes
  everything (the decided data policy). Test this condition explicitly.
- **Secret hygiene:** `REGISTRATIONKEY` is `Hidden`, but the SetProperty-generated command line
  lands in the property named `BootstrapConfig` — declare
  `<Property Id="BootstrapConfig" Hidden="yes"/>` too, or the key leaks into `/l*v` logs.

### 4.4 New Go subcommands (thin, MSI-only)

Two ~40-line subcommands in a new `install/msi_windows.go`, dispatched from
`cmd/certkit-agent/main.go` (Windows-only; stub error elsewhere):

- `bootstrap-config --service-name --config --key`: mkdir config dir; if config missing,
  require `--key` (exit non-zero with `"REGISTRATIONKEY is required for first install"` — that
  becomes the MSI's rollback error) and call the existing `config.CreateInitialConfig` +
  `config.SetBootstrapServiceName`. **No SCM, no event log, no registry, no service start** —
  the MSI owns all of that.
- `msi-cleanup --config`: existing best-effort `unregisterAgent(configPath)` API call, then
  remove `config.json` and `%ProgramData%\CertKit`. Errors logged, exit 0.

Why not reuse `certkit-agent install` (it even has `--key` already)? Inside the MSI it would
fight `ServiceInstall` for service ownership, redundantly rewrite the service's
BinaryPathName, start the service out-of-sequence, and its `log.Fatalf` failure modes produce
terrible MSI diagnostics. `install`/`uninstall` stay exactly as they are for Linux and the
`-Binary` fallback.

### 4.5 Installer UI

`CertKitUI` (`packaging/windows/CertKitUI.wxs`) — a copy of the stock `WixUI_InstallDir`
flow (the documented WiX customization route) with the branded banner/dialog bitmaps,
`license.rtf`, and one addition: a **registration-key page** between the directory and
summary pages. An AppSearch file search sets `CONFIGEXISTS` when
`%ProgramData%\CertKit\certkit-agent\config.json` is already present, and the key page is
skipped in that case — attended upgrades and migrations never see it. On fresh machines,
Next is blocked with a message until a key is entered (an empty key would otherwise fail
and roll back at the BootstrapConfig action). Silent installs (`/qn`) never show UI and
keep using the `REGISTRATIONKEY` property.

## 5. Event Viewer

We already have an event source: classic source `CertKit` in the **Application** log, registered
by `install/windows.go`, written by `cmd/certkit-agent/eventlog_windows.go` (every `log.Printf`
→ event ID 1, Information, full text as the insertion string). The options ladder:

- **(a) Recommended — formalize what exists.** Keep the `CertKit` source in the Application log
  and let the MSI own its registration via `util:EventSource` (§4.2). Rendering already works:
  `EventCreate.exe`'s message template for event ID 1 passes our text through cleanly, so there
  is no rendering problem to fix — only ownership to formalize. The Go-side
  `ensureWindowsEventLogSource` stays for the fallback path; it writes the same registry values,
  so the two never conflict.
- **(b) Later nicety — dedicated log.** A custom classic log (`util:EventSource Log="CertKit"`)
  appears under "Applications and Services Logs" as its own CertKit log. Costs: the new log
  only appears after an EventLog-service restart or reboot, and it splits history across the
  migration. Not worth it now; easy to revisit.
- **(c) Rejected — ETW instrumentation manifest.** A "real" manifest-based provider
  (mc.exe-compiled, `wevtutil im`) requires abandoning the classic ReportEvent API and rewriting
  the agent's logging layer. Over-engineering for what we get.
- **Optional polish (Phase 6):** a tiny CertKit-branded message DLL (or an
  RT_MESSAGETABLE embedded in the exe via mc.exe + windres — note `go-winres` cannot emit
  message tables, so this adds a toolchain step) so Event Viewer's "Source" details look fully
  first-party instead of referencing EventCreate.exe.

## 6. Self-update coexistence (decided: keep exe-swap, accept drift)

The agent self-updates by swapping its own exe on disk and letting SCM recovery restart it.
Under an MSI that means the installed exe drifts from what the MSI recorded, and Add/Remove
Programs' DisplayVersion lags reality. Decision: **keep it** — customers keep zero-touch
updates, and the hazards are closed structurally:

- **Repair is disabled** (`ARPNOREPAIR=1`), so nothing can "repair" a newer self-updated exe
  back to the MSI's older copy.
- **MajorUpgrade replaces everything** on the next MSI install regardless of drift; the
  DowngradeErrorMessage guard operates on ProductVersion, not file versions, so drift never
  blocks an upgrade.
- **Litter is cleaned:** `RemoveFile` handles `certkit-agent.old.exe` / `certkit-agent.new.exe`
  on install and uninstall.
- **Documented truth:** `certkit-agent version` is authoritative; ARP DisplayVersion is
  "version at last MSI install."
- After signing ships, self-update-delivered exes are the signed release binaries, so the AV
  posture survives self-updates too.

Future milestone (not this project): self-update downloads and runs the new MSI
(`msiexec /i /qn`) instead of swapping the exe — keeps ARP truthful forever, but msiexec stops
the very service that launched it, which needs a detached-process dance. Park it.

## 7. Release workflow restructure

`.github/workflows/release.yml` goes from one build-and-release job to a three-stage pipeline
(docker job unchanged). Checksums move to the end because **signing changes file hashes**.

```yaml
jobs:
  build:                     # ubuntu-latest — as today, minus checksums
    steps:
      # checkout (fetch-depth: 0), setup-go
      # ./scripts/build.sh   (now runs go-winres first; checksum step skipped in CI)
      # upload-artifact: name=binaries, path=dist/bin/*

  package-windows:           # windows-latest, needs: build
    steps:
      # download-artifact binaries
      # Version: $ver = "${{ github.ref_name }}".TrimStart("v"); fail unless ^\d+\.\d+\.\d+$
      # SIGN certkit-agent_windows_amd64.exe        (e.g. azure/trusted-signing-action, OIDC)
      # dotnet tool install --global wix; wix extension add WixToolset.Util/UI.wixext
      # wix build packaging/windows/Package.wxs -arch x64 -d Version=$ver
      #     -d AgentExe=<signed exe> -o dist/msi/certkit-agent_windows_amd64.msi
      # SIGN the .msi
      # Smoke test (runner is admin): pre-seed a dummy config.json so bootstrap skips the
      #     key requirement; msiexec /i /qn /l*v msi.log; assert service + ARP entry exist;
      #     msiexec /x /qn; assert both gone. Upload msi.log as artifact on failure.
      # upload-artifact: name=windows-signed  (signed exe + msi)

  release:                   # ubuntu-latest, needs: [build, package-windows]
    steps:
      # download both artifacts; the SIGNED exe replaces the unsigned one in dist/bin
      # regenerate certkit-agent_SHA256SUMS.txt over the FINAL byte-for-byte file set
      # softprops/action-gh-release@v2: dist/bin/*, dist/msi/*, dist/*.txt

  docker-image:              # unchanged
```

`scripts/build.sh`'s checksum step becomes local-dev-only (skip when e.g. `SKIP_CHECKSUMS=1`),
since CI must checksum after signing. Until a signing provider is onboarded, the two SIGN steps
are simply absent (Phase 3 ships the pipeline unsigned; Phase 4 adds signing).

## 8. install.ps1 v2 — MSI installs + migration

Same user contract as today: `iwr -useb https://app.certkit.io/agent/latest/install.ps1 | iex`
from elevated PowerShell with `$env:REGISTRATION_KEY` set; downloads via the CertKit GitHub
proxy (github.com is blocked on many customer networks); SHA256-verified.

Changes:

1. **Default path installs the MSI.** Download `certkit-agent_windows_amd64.msi` +
   `certkit-agent_SHA256SUMS.txt` from the existing `github-proxy` release routes, verify, then:

   ```powershell
   msiexec /i "$msi" /qn /norestart /l*v "$env:TEMP\certkit-agent-install.log" REGISTRATIONKEY="$key"
   ```

   Pass the `REGISTRATIONKEY` property only when the env var is set (quoted — keys contain
   dots). Run via `Start-Process -Wait -PassThru`; treat exit 0 as success and 3010 as
   success-with-reboot-recommended notice; on failure, print the log path. Keep today's
   post-install "service is Running" verification and success messaging.

2. **Migration from script installs** (before msiexec). Detect legacy install: service
   `certkit-agent` exists AND the non-GUID ARP key
   `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CertKit Agent` exists AND no MSI
   product is registered. Then:
   - Stop the service (reuse today's stop/wait/verify logic), then **`sc.exe delete
     certkit-agent`** — Windows Installer's `ServiceInstall` over a pre-existing same-name
     service it doesn't own is undefined-to-hostile; always delete first.
   - Remove the legacy ARP key; delete `bin\uninstall.ps1` and `certkit-agent.old.exe`.
   - **Leave `config.json` alone.** Identity (agent_id, keypair) is preserved, so migration
     needs no REGISTRATION_KEY — say so in the script output.
   - Path/registry string comparisons must normalize the doubled-backslash quirk: the current
     script's defaults are written as `"C:\\Program Files\\CertKit"`, so existing installs have
     literal `\\` baked into service BinaryPathName and ARP `InstallLocation`.

3. **`-Binary` switch** preserves the current script's full legacy flow verbatim, as an escape
   hatch and for environments where msiexec is policy-restricted.

4. **ARM64 note:** the script's arm64 branch references `certkit-agent_windows_arm64.exe`, an
   asset no build has ever produced — that path 404s today. Proposal: ARM64 hosts install the
   amd64 MSI under Windows-on-ARM x64 emulation (see Open Questions).

**Cutover ordering:** the v2 script goes live at `app.certkit.io/agent/latest/install.ps1` only
**after** the first MSI-bearing release exists, or every install breaks. Also verify beforehand
that the proxy streams multi-MB `.msi` bodies correctly (it already streams exes).

## 9. File inventory

New files:

| Path | Purpose |
|---|---|
| `assets/certkit.ico` | Multi-res product icon (logo needed — Open Questions) |
| `winres/winres.json` | go-winres config: icon, VERSIONINFO, manifest |
| `packaging/windows/Package.wxs` | WiX authoring (§4) |
| `packaging/windows/license.rtf` | LICENSE converted for WixUI |
| `packaging/windows/banner.bmp`, `dialog.bmp` | Branded installer UI art (493×58, 493×312) |
| `install/msi_windows.go` | `bootstrap-config` + `msi-cleanup` |
| `packaging/windows/CertKitUI.wxs` | Custom dialog set: stock InstallDir flow + registration-key page |

Modified: `.github/workflows/release.yml` (§7), `scripts/build.sh` + `scripts/build.ps1`
(go-winres step; checksum relocation; the build.ps1 hardcoded-version fix), `scripts/install.ps1`
(§8), `cmd/certkit-agent/main.go` + dispatch files (two subcommands), `.gitignore` (`*.syso`),
and docs (`INSTALLATION.md`, `README.md`, `CLI-REFERENCE.md` — MSI path, GPO/Intune one-liner,
`-Binary` fallback, new subcommands).

Untouched on purpose: `install/windows.go` install/uninstall flows (Linux + fallback path),
`selfupdate/*`, the docker job.

## 10. Phased rollout

Each phase is independently shippable and verifiable.

- **Phase 0 — unblockers.** Produce logo assets; generate the UpgradeCode GUID and record it in
  this doc; **start the signing-provider eligibility check + onboarding immediately** (longest
  lead time; gates only Phase 4).
- **Phase 1 — exe branding + subcommands.** winres.json, build-script wiring,
  `bootstrap-config`/`msi-cleanup`. Verify: all three targets build; exe Properties dialog shows
  icon/version/company; `bootstrap-config` creates a valid config with `--key` and fails clearly
  without one.
- **Phase 2 — WiX authoring, local unsigned MSI.** Verify on a throwaway VM: fresh install with
  `REGISTRATIONKEY` (service running, branded ARP entry, event source registered, config
  created); upgrade x.y.z → x.y.z+1 preserves config/identity (no MsiCleanup in the log);
  uninstall removes service + ProgramData and attempts unregister; migration from a real
  script-install; `/l*v` logs never contain the registration key.
- **Phase 3 — CI, unsigned.** Workflow restructure minus SIGN steps; artifact handoff; checksum
  regeneration in the release job; runner smoke test. Verify with a test tag (`vX.Y.Z`, or
  `vX.Y.Z-<suffix>` for a prerelease — anything else is rejected): release contains exe + MSI +
  checksums that match the published bytes.
- **Phase 4 — signing.** Wire the chosen provider, exe-then-MSI. Verify:
  `Get-AuthenticodeSignature` reports Valid + timestamped on both assets; MSI still installs;
  checksums match signed bytes; optional VirusTotal submission comes back clean.
- **Phase 5 — install.ps1 v2 cutover.** Ship to app.certkit.io hosting after the first signed
  MSI release. Verify the matrix on VMs: fresh-no-key (clear failure), fresh-with-key,
  script→MSI migration (agent_id unchanged server-side), MSI→MSI upgrade, `-Binary` fallback,
  uninstall from Add/Remove Programs.
- **Phase 6 — docs + optional polish.** INSTALLATION/README/CLI-REFERENCE; registration-key
  dialog; branded message DLL; VirusTotal CI gate; MSI-based self-update design.

## 11. Open questions

1. **Logo assets** — who produces `certkit.ico` (multi-res) and the WixUI banner (493×58) /
   dialog (493×312) bitmaps?
2. **Signing provider** — confirm Azure Trusted Signing eligibility for the CertKit entity
   (3+ years verifiable history, or accept individual validation); otherwise SSL.com eSigner.
3. **Service DisplayName** — ~~open~~ **decided: branded.** The MSI sets DisplayName
   "CertKit Agent" (services.msc); the internal service name stays `certkit-agent`, so
   everything programmatic is unaffected. Cosmetic caveats: mixed fleets show mixed display
   names until fully on the MSI, and a `-Binary` fallback upgrade flips it back to
   `certkit-agent` on that machine (the Go installer rewrites DisplayName). Easy to back out —
   one attribute in Package.wxs.
4. **ARM64** — accept amd64-MSI-under-emulation for Windows-on-ARM (and fix/remove the broken
   arm64 branch in install.ps1), or add a `windows/arm64` build + second MSI?
5. **Registration-key UI dialog** — ~~open~~ **done.** `CertKitUI.wxs` adds the page;
   it appears only on fresh machines with no existing config (see §4.5).

## 12. Risks & gotchas

- **Service takeover on migration.** MSI `ServiceInstall` over a pre-existing same-name service
  misbehaves — install.ps1 must stop **and delete** the legacy service first; and legacy
  registry/service values contain literal doubled backslashes that string-matching must
  normalize.
- **Deferred custom-action context.** No user environment, no property access — the key must
  travel via Secure property + SetProperty/CustomActionData, and both `REGISTRATIONKEY` and the
  `BootstrapConfig` property must be Hidden or the key appears in verbose logs.
- **ProductVersion normalization.** Tags must be `vX.Y.Z` or `vX.Y.Z-<suffix>` (suffix
  stripped for ProductVersion; published as a GitHub prerelease). Fail loudly on
  git-describe suffixes; major/minor must be < 256. Prerelease ↔ final share a
  ProductVersion — handled by `AllowSameVersionUpgrades` (§4.1).
- **Checksum ordering.** SHA256SUMS must be generated after signing in the release job, or
  install.ps1 verification breaks on every release.
- **`NOT UPGRADINGPRODUCTCODE`.** The one condition standing between an upgrade and destroyed
  agent identity — test it explicitly in Phase 2.
- **UpgradeCode is immutable** once the first MSI ships; component GUID stability depends on
  stable install paths.
- **File costing.** The legacy on-disk exe is unversioned; the new exe's VERSIONINFO makes
  "versioned replaces unversioned" deterministic. Don't ship the MSI before the .syso work.
- **Exit code 3010.** `ServiceControl` stops the service before file copy so reboots are rare,
  but install.ps1 must still treat 3010 as success-with-notice.
- **Self-update drift.** ARP version lags after self-update; repair is deliberately disabled;
  `.old.exe`/`.new.exe` litter is cleaned by the MSI.
- **Proxy.** Confirm `app.certkit.io`'s github-proxy streams multi-MB `.msi` assets before
  cutover.
