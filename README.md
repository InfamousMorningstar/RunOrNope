# RunOrNope

RunOrNope is a security-sensitive Windows desktop static analyzer for explaining
what an untrusted executable or installer appears capable of doing. Its central
promise is simple: submitted samples are **never executed** and **never
uploaded** during local analysis.

## Current status

This repository currently contains only the reproducible .NET 10 solution
foundation and project-boundary test. It does not yet scan files, provide a
usable desktop application, isolate a worker, produce verdicts, or generate
reports. Those capabilities remain roadmap items.

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

The WPF project deliberately has no reference to parser projects. The planned
broker will open each sample once and start a capability-free AppContainer
worker under Job Object limits. Hostile worker output will cross back only as
bounded, validated contract data. Isolation failures will fail closed.

## Build prerequisites

- Windows 10 or Windows 11 on x64
- PowerShell
- The pinned .NET SDK 10.0.302

Install the repository-local SDK with Microsoft's official installer:

```powershell
New-Item -ItemType Directory -Path .tools -Force | Out-Null
Invoke-WebRequest -Uri "https://dot.net/v1/dotnet-install.ps1" -OutFile ".tools\dotnet-install.ps1"
& .\.tools\dotnet-install.ps1 -Version "10.0.302" -InstallDir ".tools\dotnet" -NoPath
& .\.tools\dotnet\dotnet.exe --version
```

Restore, build, and test:

```powershell
& .\.tools\dotnet\dotnet.exe restore --use-lock-file
& .\.tools\dotnet\dotnet.exe restore --locked-mode
& .\.tools\dotnet\dotnet.exe build -c Release --no-restore
& .\.tools\dotnet\dotnet.exe test -c Release --no-build
```

## Privacy and safety model

Local analysis is planned to have no network access and must not execute, load,
install, repair, shell-open, preview, or resolve sample-controlled content.
No file upload is planned. A future, separate VirusTotal action may disclose
only the SHA-256 hash after explicit confirmation; it will never upload a
sample. Reports may contain sensitive extracted evidence and will require clear
privacy controls.

## Current limitations

- No analyzer or user interface has been implemented.
- No worker isolation or hostile-output validation has been implemented.
- No serviced Windows build matrix has been published.
- No security claim should be inferred from this scaffold.
- Risk disposition and analysis completeness contracts are not implemented yet.

## Roadmap

1. Immutable, bounded evidence and verdict contracts.
2. Single-handle intake with identity and mutation checks.
3. Fail-closed AppContainer and Job Object worker isolation.
4. Read-only PE/CLR, MSI, and bounded nested-content analysis.
5. Evidence-backed capability rules and YARA-X integration.
6. Script-free JSON/HTML reporting with privacy controls.
7. WPF workflow, accessibility, packaging, CI, and security documentation.
