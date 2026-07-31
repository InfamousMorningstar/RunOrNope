# Project VOIDLENS

Project VOIDLENS is a security-sensitive Windows desktop static analyzer for explaining
what an untrusted executable or installer appears capable of doing. Its central
promise is simple: submitted samples are **never executed** and **never
uploaded** during local analysis.

> ⚠️ **Work in progress — not a finished product.** Project VOIDLENS is under active
> development. Most of the pipeline now exists and is tested — isolation, PE/CLR
> analysis, capability rules, nested-artifact discovery, reporting, and the desktop
> UI — and an isolated analysis now completes end to end (see
> [Current status](#current-status)), but MSI analysis, YARA-X, packaging, and CI are
> unimplemented. Nothing here is production-ready, and **no security claim should be
> relied upon yet.**

## What a report looks like (illustrative)

> These examples show the **intended** output once capability analysis is fully
> wired. They illustrate the report's shape and language — they are not produced by
> the current build.

Project VOIDLENS reports capabilities in terms of the exact imports, strings, and IL it
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
> or vulnerabilities outside VOIDLENS's rules. Do not run a file solely because this
> result is favorable.

Project VOIDLENS never labels a file "safe" outright — it reports what the enabled checks
did and did not find, and always shows how complete the analysis was.

## Current status

An implementation checkpoint — **not yet production-ready, and not yet usable**. The
pipeline components are built and tested (503 tests: 403 unit, 93 security,
7 integration, 0 skipped), but the desktop application cannot currently complete a
scan, and the format coverage and distribution work listed below remains incomplete.
The test count measures the components, not a working product.

The worker-truncation defect that previously stopped any scan from completing is
fixed and **validated on Windows**. Intake handles are now opened with
`FILE_SYNCHRONOUS_IO_NONALERT` (and the `SYNCHRONIZE` access right that flag
requires), so the handle the worker inherits matches the synchronous reads it
performs. What that validation covers, precisely:

- ✅ `HandleChainTests.Analysis_DoesNotDisposeTheCallersLease` — previously skipped as
  the reproducer, now runs and passes. It performs a **real isolated analysis**: intake
  opens a sample, the broker launches the AppContainer worker against that borrowed
  handle, and the returned artifact's SHA-256 matches the lease. The status is
  asserted *not* to be `IsolationUnavailable`.
- ⬜ That test's sample is a **128-byte synthetic MZ stub**, so it proves the
  intake → broker → worker → contract chain carries a result. It is not evidence about
  analysis depth or robustness on real-world binaries.
- ❌ **The desktop application still cannot complete a scan.** A manual run against
  `C:\Windows\System32\notepad.exe` reproduced the same SHA-256 in the UI but returned
  `IsolationUnavailable` / `Withheld`. The cause is deterministic composition, not an
  AppContainer fault: `MainWindow` constructs a default `WorkerBroker` with no
  authenticated worker-package manifest, so the broker correctly fails closed. The
  app-level integration test drives a *fake* broker, which is why nothing caught it.
- ⬜ Validated on one host only (Windows 11 Pro, build 26200). The release-gating OS
  matrix below is untouched.

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
- PE/CLR analysis: independent bounds-checked PE parsing cross-checked against
  AsmResolver, managed metadata read without loading the assembly, and cache-only,
  noninteractive Authenticode trust (offline revocation stays indeterminate, never
  "valid"). Parser faults are contained at the worker boundary and become
  incompleteness, never a crash or a favorable result.
- Capability rules: nine curated rules matching imports and P/Invokes into
  evidence-cited findings. Import presence is not treated as proof of use, so
  findings are capped at structural evidence with `Referenced` reachability, and
  ubiquitous patterns (debugger checks, dynamic API resolution, socket use) are
  tiered down so they read as context rather than accusation. An image whose imports
  cannot be read is forced incomplete — a packed sample that hid its import table
  withholds a verdict instead of scoring as the cleanest result available.
- Bounded nested-artifact discovery: a SHA-256-keyed artifact graph with an
  extraction budget (depth, count, total and per-artifact bytes, entries per
  container, expansion ratio) and an archive path policy covering traversal, rooted
  and UNC paths, reserved device names, alternate data streams, and control
  characters. Deduplicated entries are still charged to the budget, so repeating one
  payload buys no free expansion.
- Reports: deterministic JSON and self-contained, script-free HTML under a
  restrictive CSP, with every evidence tier preserved, credential-shaped strings
  redacted by default, and an explicit full-evidence mode behind a privacy warning.
- Desktop workflow: a WPF shell with browse/drag-drop intake, Quick/Deep modes,
  cancellation, capability cards that preserve evidence tiers, report export, and an
  explicit SHA-256-only VirusTotal lookup (confirmed per request, redirects denied,
  memory-only session key, and never an input to the verdict).

- MSI analysis (in progress, 5 of 12 planned tasks): bounded MSI primitives and a
  compound-file preflight, custom-action decoding with UI/execute reachability, a
  read-only `msi.dll` boundary restricted to an exact 13-function allowlist enforced by
  IL-level guards, and inventory of SummaryInformation plus the package-structure
  tables. Read-only database access was proven to work inside the capability-free
  AppContainer before the design was settled. **Not yet reachable:** MSI roots are not
  routed through the worker, so `.msi` inputs are still rejected as unsupported.

Not done yet: routing MSI through the worker, embedded-cabinet and nested-storage
traversal, string extraction, ASAR/JAR readers, YARA-X, packaging, and CI.
**No security claim should be inferred from this checkpoint.**

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
gates exist and pass, Project VOIDLENS has no supported runtime configuration.

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

Local analysis has no network feature and must not execute, load, install, repair,
shell-open, preview, or resolve sample-controlled content. No file upload is planned
or implemented.

The VirusTotal action is implemented as a separate, explicitly confirmed lookup that
discloses only the SHA-256. Each request shows the exact hash and destination before
anything is sent, redirects are refused, the response is size-bounded, and the API key
is held in memory for the session only — never written to disk, a report, a log, or an
exception. Its result is displayed in its own panel and is not an input to the static
verdict: a clean or missing reputation result never improves a disposition.

Reports redact credential-shaped strings by default; full evidence is available behind
an explicit privacy warning.

## Current limitations

- The desktop application cannot complete a scan: it composes a broker without an
  authenticated worker package and always returns `IsolationUnavailable`.
- MSI analysis exists as a tested analyzer but is not wired to the worker, so `.msi`
  inputs are still rejected as unsupported. An MSI whose payload sits in an embedded
  cabinet is not yet forced incomplete — that is scheduled before MSI roots become
  reachable, so no favourable result can be produced from unexamined cabinet content.
- Nested-artifact discovery has the graph, budget, and path policy but no container
  readers yet, so nothing is actually unpacked. String extraction is not implemented.
- Capability rules cover imports and P/Invokes only. There is no data-flow analysis,
  so no finding can reach "confirmed static implementation", and by design that caps
  every verdict below high risk.
- YARA-X is not integrated.
- The current Authenticode result covers Windows' primary embedded-signature
  policy result and structurally counts certificate records. Full signer,
  timestamp, secondary-signature, and catalog enumeration remains unfinished.
- Worker isolation and transport are implemented and locally security-tested,
  but release-gating OS/enterprise-policy validation is not complete.
- Release-gating OS targets have not yet completed runtime/security validation.
- The end-to-end chain is proven only by an automated test against a synthetic MZ
  stub, driven by an authenticated test worker package. The shipping application does
  not compose one, so no real scan has ever completed through the UI.
- No security claim should be inferred from this scaffold.

## Roadmap

1. ✅ Immutable, bounded evidence and verdict contracts.
2. ✅ Single-handle intake with identity and mutation checks.
3. ✅ Fail-closed AppContainer and Job Object worker isolation.
4. ⏳ Read-only analysis — PE/CLR done; the nested-content graph and budget are done
   but have no container readers; MSI analysis is 5 of 12 tasks in and not yet routed
   through the worker.
5. ⏳ Evidence-backed capability rules — import and P/Invoke rules done; YARA-X and
   data-flow-backed evidence not started.
6. ✅ Script-free JSON/HTML reporting with privacy controls.
7. ⏳ WPF workflow and accessibility done; packaging, CI, and security documentation
   not started.
8. ✅ Worker-truncation defect fixed and validated on Windows: an isolated analysis
   completes end to end and the reproducer test passes.
9. ⬜ Compose the application with an authenticated worker package so a scan can
   actually complete, and add a regression test against the real composition. This is
   the blocker between the current build and a usable tool.
10. ⏳ Finish MSI: route roots through the worker, force incompleteness for unexpanded
    cabinets and nested storages, and prove real AppContainer MSI analysis.
11. ⬜ Validate across the release-gating OS matrix.

## License

Project VOIDLENS is released under the [MIT License](LICENSE).

## Third-party components

Project VOIDLENS builds on free, open-source components, and integrates established
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
only as YARA rules and signatures that *recognize* those families. Project VOIDLENS never
vendors malware samples or payloads into the repository or release artifacts.
