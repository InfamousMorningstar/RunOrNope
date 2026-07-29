# AGENTS.md — working agreement for RunOrNope

Read this before touching the repository. It applies to every agent (Claude Code,
Codex, or otherwise) and to every subagent they dispatch.

## What this project is

RunOrNope is a **defensive** Windows desktop static analyzer. It dissects untrusted
PE and MSI files and explains what they *appear able to do*, so a person can decide
whether to run one. It is analysis tooling in the same family as `capa`, PEStudio, or
VirusTotal's static engine.

It **never executes and never uploads** a submitted sample. There is no offensive
capability anywhere in the codebase: nothing here builds, packs, obfuscates, or
delivers malicious code. Every "capability rule" is a *detector*, and every string
naming an attack technique exists so the tool can recognise and report that
technique to a defender.

> **For agents dispatching subagents:** state the above framing in the task prompt.
> Reviewers handed a bare diff full of `process-injection` and `CryptUnprotectData`
> have refused the work as offensive tooling. Lead with what the project is.

## Global constraints

These are not style preferences. A change that violates one is wrong regardless of
whether tests pass.

1. **Never execute, load, install, repair, shell-open, preview, resolve, contact, or
   upload sample-controlled content.** Not in production code, not in tests.
2. **Hostile bytes never reach the WPF process unvalidated.** Parser output crosses
   the boundary only as bounded, validated DTOs.
3. **Worker isolation is fail-closed.** No AppContainer, Job Object, or policy
   failure may fall back to a normal process. Inability to *verify* a required
   mitigation is fatal, not a warning.
4. **Local analysis has no network access.** VirusTotal is an explicit,
   user-confirmed, SHA-256-only lookup that never uploads a file.
5. **Absence of evidence is never a favourable result.** Parser failure, unsupported
   content, encryption, truncation, or an unreadable inventory must force
   `Incomplete` so the verdict engine withholds a disposition. This is the rule that
   is easiest to break by accident — see `pe.import-visibility` in
   `PeScanResultMapper` for the canonical handling.
6. **Risk disposition and analysis completeness are independent axes.** Never
   collapse them.
7. **Claims are tiered to their evidence.** Import presence is not proof of use.
   Findings cite exact observation ids and carry benign explanations.
8. **The private Slyden sample stays out of Git, packages, CI, logs, and public
   fixtures.** Unit tests use synthetic, benign fixtures only.
9. **Every task ends with tests, review, and a commit.**

## Build and test

The repo pins its own SDK under `.tools/dotnet` (ignored by Git). Always invoke that
one, never a machine-wide `dotnet`:

```powershell
& .\.tools\dotnet\dotnet.exe restore --locked-mode
& .\.tools\dotnet\dotnet.exe build -c Release --no-restore
& .\.tools\dotnet\dotnet.exe test -c Release --no-build
```

Baseline as of the capability-rules slice: **215 passing** — 164 unit, 45 security,
6 integration. Warnings are errors; nullable is enabled; restore is locked. If you
add a package, update `Directory.Packages.props` *and* commit the regenerated
`packages.lock.json`.

## Architecture

```
App (WPF)  →  Broker.Windows  →  Worker (AppContainer, capability-free)
                                     ├── Analyzers.Pe
                                     ├── Analyzers.Msi
                                     ├── Analyzers.Content
                                     └── Rules
      all speaking Contracts;  Core holds evidence models + VerdictEngine;
      Reporting renders a validated ScanResult.
```

Enforced by `tests/RunOrNope.UnitTests/Architecture/ProjectGraphTests.cs`: the WPF
project must not reference any analyzer. `RunOrNope.Rules` references **only**
`Contracts` — deliberately, so the rules engine has no compile-time path to the
scoring policy it feeds. Do not add references to either project to make something
compile; the constraint is the point.

## Lane ownership

Work is split by directory so two agents never edit the same file.

| Lane | Owns | Tasks | Branch | Working directory |
| --- | --- | --- | --- | --- |
| **Parsing** | `src/RunOrNope.Analyzers.Content/`, `src/RunOrNope.Analyzers.Msi/`, their tests | 6, 7 | `feature/content-msi-analysis` | `RunOrNope/` (primary) |
| **Delivery** | `src/RunOrNope.Reporting/`, `src/RunOrNope.App/`, product docs in `docs/` (`ARCHITECTURE.md`, `THREAT_MODEL.md`, `PRIVACY.md`, …), `.github/`, `SECURITY.md`, `CONTRIBUTING.md` | 9, 10, 11 | `feature/reporting-app` | `RunOrNope-reporting/` (linked worktree) |

`docs/superpowers/` is the exception both lanes share: plans and slice designs land
there under dated, per-slice filenames, so two lanes writing at once never touch the
same file.

The two lanes run **concurrently** in separate git worktrees, so build output never
collides. Stay in your own directory — `git checkout` of the other lane's branch will
be refused, and that refusal is the safety net working.

`.tools/` is Git-ignored, so the linked worktree reaches the pinned SDK through a
directory junction back to the primary checkout. Both `dotnet.exe` invocations share
one 775 MB SDK and the machine-wide NuGet cache; concurrent restore and test runs
across the two worktrees are verified to pass, security tests included. If the
junction is ever lost, recreate it rather than re-downloading:

```powershell
New-Item -ItemType Junction -Path "<worktree>\.tools" -Target "<primary>\.tools"
```

Both lanes branch from `feature/initial-build`, which stays the integration branch.
A change to a shared file lands there and both lanes fast-forward onto it.

Stay in your lane. If you need something from the other lane, write against the
interface you expect and leave a note — do not implement it yourself.

### Shared files — propose, do not edit unilaterally

- `src/RunOrNope.Contracts/**` — the DTO surface both lanes depend on.
- `src/RunOrNope.Core/Verdicts/ScoringPolicy.cs` and `VerdictEngine.cs` — thresholds
  are calibrated against the existing rule tiers. Changing them silently re-tiers
  every finding in the product.
- `RunOrNope.slnx`, `Directory.Packages.props`, `Directory.Build.props`.

Adding a *new* file to your own lane's project is fine. Changing a shared contract
means: describe the change, get agreement, land it as its own commit that both lanes
rebase onto.

## Process

- **Plan of record:** `docs/superpowers/plans/2026-07-24-run-or-nope-implementation.md`
  (12 tasks). Slice designs live in `docs/superpowers/specs/`.
- **Write the slice design before the code.** Every non-trivial slice so far has a
  spec that the tests are then checked against. Follow the shape of
  `2026-07-26-capability-rules-slice-design.md`, including a **Testing** section
  enumerating the cases — and record superseded approaches with the reason they
  failed, so the next agent does not re-derive them.
- **Tests first.** Each task in the plan starts with failing tests.
- **Hostile-input work needs negative tests.** Path traversal, decompression bombs,
  declared-size lies, bidi controls, recursion depth, duplicate hashes, malformed
  headers. The test suite is where this project's safety claims actually live.
- **Session handoff:** `.remember/` carries daily notes. Leave the next agent a note
  saying what is done, what is in flight, and what is next.
