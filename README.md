# RunOrNope

RunOrNope is a security-sensitive Windows desktop static analyzer for explaining
what an untrusted executable or installer appears capable of doing. Its central
promise is simple: submitted samples are **never executed** and **never
uploaded** during local analysis.

## Current status

This repository currently contains the reproducible .NET 10 solution,
bounded evidence/verdict contracts, single-handle file intake, and the first
fail-closed Windows worker-isolation layer. Intake opens
an input read-only while denying write and delete sharing, records stable
Windows identity and metadata, accepts local filesystems only, walks every path
component by held directory handle without following reparse points, opens the
final file relative to its verified parent, hashes through that owned handle,
and identifies PE or structurally plausible compound-file
candidates by bytes instead of extension. A compound-file candidate is not
claimed to be an MSI until the future MSI analyzer validates it.

The broker can create a unique capability-free AppContainer profile, an
inheritance-protected output directory limited to the broker and worker SIDs,
and a Job Object with one-process, memory, CPU, and kill-on-close limits. It
builds a suspended worker with an explicit four-handle allowlist (sample,
private output directory, request pipe, response pipe), assigns the Job before resuming, and exchanges
versioned length-prefixed UTF-8/JSON frames whose size is checked before
allocation. A streaming token pass rejects duplicate members, excessive depth,
strings, collections, per-object member counts, and aggregate token counts
before contract objects are materialized. While the
worker is still suspended, the broker verifies its AppContainer token, exact
package SID, zero capabilities, Job membership and limits, effective
mitigations, and child-process restriction. Any setup, launch, timeout,
protocol, or result-validation failure
returns `IsolationUnavailable`; there is no ordinary-process fallback.

This is still an implementation checkpoint, not a usable scanner because the
actual analyzers and UI are not wired yet. The isolation transport itself now
completes with a self-contained authenticated worker bundle. Every package file
is named and SHA-256 hashed in a canonical P-256 ECDSA-signed manifest. Strict
Windows filename checks reject device names, invalid/trailing characters,
case collisions, and non-ASCII normalization ambiguity. Files are staged from
held read-only source handles into a unique worker-readable package directory,
flushed, hashed again, sealed read/execute-only, and held against write/delete
replacement through worker termination. The broker also verifies the suspended
process image is the exact staged entrypoint. Callers must supply the trusted public key from
their application trust root; trusting a key stored beside the package would
defeat the signature.

The live security suite uses local listeners and a dedicated generated probe
bundle—never a malware sample—to verify denial of IPv4, IPv6, loopback, private
LAN, HTTP, explicit proxy, WebSocket, DNS packet delivery, child-process creation, and
unexpected inherited handles. It also verifies safe output writes, traversal
and reparse denial, memory/CPU/wall-clock limits, and Job kill-on-close. On this
Windows build, Winsock accepts the isolated raw UDP DNS send locally but the
controlled listener receives zero bytes; the test measures observed egress
instead of mislabeling a resolver error as network denial. Worker termination
is awaited before cleanup, and startup scavenging only removes strictly named,
ACL-private RunOrNope resources older than 24 hours.

## Planned supported root formats

- Windows PE files: `.exe`, `.dll`, `.scr`, and `.sys`
- Windows Installer databases: `.msi`

Nested content may eventually be identified and analyzed under explicit limits,
but archives and other formats are not planned as root inputs. Unsupported or
invalid roots will produce an incomplete/unsupported analysis, never a
favorable verdict.

## Architecture

The intended trust boundaries are represented by the project graph:

```text
RunOrNope.App (WPF presentation)
    |-- Contracts / Core / Reporting
    `-- Broker.Windows -- Intake
                         |
                         `-- restricted Worker (separate process)
                              |-- PE analyzer
                              |-- MSI analyzer
                              |-- content analyzer
                              `-- Rules
```

The WPF project deliberately has no reference to parser projects. The broker
opens each sample once and passes only a duplicate of that existing handle to a
capability-free AppContainer worker under Job Object limits. Hostile worker
output crosses back only as bounded, validated contract data. Isolation
failures fail closed.

## Build prerequisites

- An x64 host listed in the build matrix below for release-gating work
- PowerShell
- The pinned .NET SDK 10.0.302

### Windows build matrix

The target framework's `windows10.0.19041.0` suffix is the minimum Windows API
contract available to compiled code. It is not a claim that every Windows build
from 19041 onward is supported.

| Edition | OS build | Foundation status |
| --- | ---: | --- |
| Windows 11 Pro | 26200 | Locally validated for SDK restore, Release build, and unit tests on x64 |
| Windows 10 Enterprise LTSC 2021 | 19044 | Release-gating target; not yet validated |
| Windows 11 Enterprise 24H2 | 26100 | Release-gating target; not yet validated |
| All other Windows editions and builds | Any | Unverified; no compatibility claim |

This foundation validation covers only restore, compilation, and the project
graph test. Before a release, every release-gating target must pass the planned
AppContainer, Job Object, mitigation-policy, WinTrust, read-only MSI, long-path,
and enterprise-policy suites on a then-serviced patch level. The exact serviced
revision and servicing state will be recorded in release evidence; until those
gates exist and pass, RunOrNope has no supported runtime configuration.

Install the repository-local SDK with Microsoft's official installer:

```powershell
New-Item -ItemType Directory -Path .tools -Force | Out-Null
Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile ".tools\dotnet-install.ps1"
& .\.tools\dotnet-install.ps1 -Version "10.0.302" -InstallDir ".tools\dotnet" -NoPath
& .\.tools\dotnet\dotnet.exe --version
```

Restore, build, and test:

```powershell
& .\.tools\dotnet\dotnet.exe restore
& .\.tools\dotnet\dotnet.exe build -c Release --no-restore
& .\.tools\dotnet\dotnet.exe test -c Release --no-build
```

Locked restore is enforced centrally, so an ordinary `restore` fails if a
dependency declaration and its committed lock file disagree. When deliberately
changing dependencies, regenerate lock files explicitly and review their diff:

```powershell
& .\.tools\dotnet\dotnet.exe restore -p:RestoreLockedMode=false --force-evaluate
& .\.tools\dotnet\dotnet.exe restore
```

## Privacy and safety model

Local analysis has no network feature and must not execute, load,
install, repair, shell-open, preview, or resolve sample-controlled content.
No file upload is planned. A future, separate VirusTotal action may disclose
only the SHA-256 hash after explicit confirmation; it will never upload a
sample. Reports may contain sensitive extracted evidence and will require clear
privacy controls.

## Current limitations

- Intake identifies root structure and hashes it, but no analyzer or user interface has been implemented.
- Worker isolation and transport are implemented and locally security-tested,
  but release-gating OS/enterprise-policy validation is not complete.
- Release-gating OS targets have not yet completed runtime/security validation.
- No security claim should be inferred from this scaffold.
- Contracts and intake are not yet wired into an end-to-end scan.

## Roadmap

1. Immutable, bounded evidence and verdict contracts.
2. Single-handle intake with identity and mutation checks.
3. Fail-closed AppContainer and Job Object worker isolation.
4. Read-only PE/CLR, MSI, and bounded nested-content analysis.
5. Evidence-backed capability rules and YARA-X integration.
6. Script-free JSON/HTML reporting with privacy controls.
7. WPF workflow, accessibility, packaging, CI, and security documentation.
