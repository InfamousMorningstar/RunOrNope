# RunOrNope

RunOrNope is a security-sensitive Windows desktop static analyzer for explaining
what an untrusted executable or installer appears capable of doing. Its central
promise is simple: submitted samples are **never executed** and **never
uploaded** during local analysis.

> ⚠️ **Work in progress — not a finished product.** RunOrNope is under active
> development. The fail-closed isolation core and the PE/CLR analyzer exist and are
> tested, but the end-to-end scan, capability rules, YARA-X, and the UI are not
> finished. Nothing here is production-ready, and **no security claim should be
> relied upon yet.**

## What a report looks like (illustrative)

> These examples show the **intended** output once capability analysis is fully
> wired. They illustrate the report's shape and language — they are not produced by
> the current build.

RunOrNope reports capabilities in terms of the exact imports, strings, and IL it
found, never as claims about what a file "did." Each line expands to the precise
evidence — imported APIs, decoded strings, call sites, byte offsets — and an
evidence tier, so a reviewer can check every claim.

### Scanning a malware sample (e.g. an information stealer)

**Verdict: High-risk static indicators** · Analysis: Complete within v1 policy

- **Discord targeting** — pulls information from Discord and restarts the Discord
  client; collects Discord account and friend information
- **Credential access** — decrypts passwords and browser data from Chrome-style
  browsers; decrypts Firefox passwords through Firefox's NSS system; reads browser
  cookies and login databases
- **Filesystem discovery & staging** — searches through Desktop and Documents;
  collects files for exfiltration
- **Data exfiltration & C2** — uploads collected files; receives remote commands
  over an encrypted WebSocket connection
- **Surveillance** — takes screenshots; accesses the webcam
- **Process manipulation** — kills processes; injects code into another process;
  spoofs process information to help hide what was running
- **Privilege & tokens** — impersonates Windows security tokens
- **Persistence & system config** — reads and changes the Windows Registry
- **Destructive behavior** — encrypts, renames, overwrites, and truncates files

**Recommended action:** do not run the file; verify its provenance or escalate to a
qualified reviewer.

### Scanning legitimate software

**Verdict: Few material static concerns identified** · Analysis: Complete within v1 policy

- Valid Authenticode signature; Windows platform trust verified the signer
- Network use limited to update checks over HTTPS to the vendor's own domain
- No credential-store access, process injection, surveillance, or destructive
  capabilities found by the enabled checks

> No material concerns were identified by the enabled static checks. This does not
> rule out malicious behavior, downloaded components, environment-dependent actions,
> or vulnerabilities outside RunOrNope's rules. Do not run a file solely because this
> result is favorable.

RunOrNope never labels a file "safe" outright — it reports what the enabled checks
did and did not find, and always shows how complete the analysis was.

## Current status

An implementation checkpoint — **not yet a usable scanner**. The security-critical
building blocks are in place and tested; the analyzers and UI are not wired into an
end-to-end scan yet.

Done so far:

- Reproducible .NET 10 solution with bounded, immutable evidence/verdict contracts.
- Single-handle file intake: opens the input read-only (deny write/delete sharing),
  records stable Windows identity, walks paths by held handle without following
  reparse points, and detects format by bytes rather than extension.
- Fail-closed worker isolation: a capability-free AppContainer under a kill-on-close
  Job Object (one process, memory/CPU/wall-clock limits), launched suspended with a
  four-handle allowlist and a signed, hash-verified worker package. Token, SID,
  capabilities, Job limits, and mitigations are all verified before resume; any
  failure returns `IsolationUnavailable` with no ordinary-process fallback. A live
  security suite (using a generated probe, never malware) checks network, child-process,
  traversal, reparse, resource-limit, and handle denials.
- First PE/CLR analyzer slice: independent bounds-checked PE parsing cross-checked
  against AsmResolver, managed metadata read without loading the assembly, and
  cache-only, noninteractive Authenticode trust (offline revocation stays
  indeterminate, never "valid").

Not done yet: MSI, nested-content, and capability analyzers; YARA-X; the end-to-end
scan; and the WPF UI. **No security claim should be inferred from this scaffold.**

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

- PE/CLR analysis is an isolated component but is not yet wired through the
  worker protocol or user interface. MSI, nested-content, and capability
  analyzers are not implemented.
- The current Authenticode result covers Windows' primary embedded-signature
  policy result and structurally counts certificate records. Full signer,
  timestamp, secondary-signature, and catalog enumeration remains unfinished.
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

## License

RunOrNope is released under the [MIT License](LICENSE).

## Third-party components

RunOrNope builds on free, open-source components, and integrates established
open-source security tools rather than reinventing them. Every dependency's
license is recorded in [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md); all are
free to use and redistribute, and licenses are re-verified before each release.

- **Currently bundled:** AsmResolver.PE (MIT) for PE parsing; JsonSchema.Net (MIT).
- **Test-only:** AwesomeAssertions (Apache-2.0), xUnit (Apache-2.0), and the .NET
  test SDK (MIT). None ship in the application.
- **Planned, license-cleared security integrations:** YARA-X (BSD-3-Clause) with
  curated, versioned rule packs; innoextract (zlib) and 7-Zip (LGPL-2.1+) as
  isolated extraction adapters.

Malware-family detection (for example information-stealer families) is carried
only as YARA rules and signatures that *recognize* those families. RunOrNope never
vendors malware samples or payloads into the repository or release artifacts.
