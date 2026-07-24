# RunOrNope

RunOrNope is a security-sensitive Windows desktop static analyzer for explaining
what an untrusted executable or installer appears capable of doing. Its central
promise is simple: submitted samples are **never executed** and **never
uploaded** during local analysis.

## Current status

This repository currently contains the reproducible .NET 10 solution,
bounded evidence/verdict contracts, and single-handle file intake. Intake opens
an input read-only while denying write and delete sharing, records stable
Windows identity and metadata, hashes through that owned handle, and detects
PE/CFBF structure by bytes instead of extension. It does not yet provide a
usable desktop application, isolated parser worker, full analyzers, or reports.

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
opens each sample once; a later milestone will start a capability-free AppContainer
worker under Job Object limits. Hostile worker output will cross back only as
bounded, validated contract data. Isolation failures will fail closed.

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
- No worker isolation or hostile-output validation has been implemented.
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
