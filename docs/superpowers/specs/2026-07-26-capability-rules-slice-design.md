# Capability Rules Slice — Design

**Date:** July 26, 2026
**Status:** Approved design, pending written-spec review
**Parent design:** `docs/superpowers/specs/2026-07-24-run-or-nope-design.md`
**Builds on:** `docs/superpowers/specs/2026-07-24-pe-structural-scan-slice-design.md`

## 1. Purpose

Turn imported APIs and CLR P/Invokes into `CapabilityFinding`s that feed the
existing `VerdictEngine`, so RunOrNope reports what a file *appears able to do* —
honestly, at the "Caution" tier. This is the first evidence-to-capability layer; it
uses code-defined, capa-style rules and import/P-Invoke cluster detection only.

## 2. Scope

In scope:

- Per-import and per-P/Invoke observations emitted by the PE mapper.
- A code-defined capability rule model and a deterministic matching engine in
  `RunOrNope.Rules` (depends only on `RunOrNope.Contracts`).
- A curated first rule set.
- `WorkerScan` assembling findings into the final `ScanResult`.

Out of scope (later slices): IL data-flow / "Confirmed static implementation",
data-driven/packaged rule files, string and configuration analysis, reachability
analysis, MSI capabilities, and any change to the verdict thresholds.

## 3. Evidence honesty and verdict interaction

Import (or P/Invoke) presence is **not** proof a capability is used. Findings in
this slice therefore use `EvidenceStatus` of at most `StrongStructuralEvidence`
(clusters) or `ApiOrLibraryPresenceOnly` (single APIs), `Reachability.Referenced`,
and carry explicit benign explanations. `VerdictEngine.DetermineDisposition`
already requires `ConfirmedStaticImplementation` + `Critical` severity + two strong
families for `HighRisk`, so this slice can only produce `CautionWarranted` (or
`FewMaterialStaticConcerns`). That ceiling is intentional and must not be worked
around. The verdict engine and its thresholds are **not** modified.

## 4. Mapper additions (`RunOrNope.Analyzers.Pe/PeScanResultMapper`)

Add two observation kinds inside `Map` (structural observations are unchanged),
so findings have concrete evidence to cite. Both go through `CleanText` and are
sourced to the root artifact like every other observation, and continue the same
deterministic `pe-obs-NNNN` id sequence.

- `pe.import` — one per entry in `analysis.RichSummary.Imports`, description exactly
  the existing `"module.dll!Api"` string.
- `pe.pinvoke` — one per `analysis.Clr.ExternalReferences` whose
  `SourceKind == "P/Invoke implementation"`, description the existing
  `"Api from module.dll"` string, with `" (app-called)"` appended when
  `DirectlyCalledByApplication` is true.

Cap the combined count of these evidence observations at 4096. If the available
imports/P-Invokes exceed the cap, emit up to the cap and add a limitation that
forces `Incomplete` (a matchable API may have been dropped — a completeness event,
never a favorable result). The existing `RichSummary.Imports` 10,000-item cap in
`PeAnalyzer` still applies upstream.

The API-name form is canonical: native `pe.import` is `module!Api` (split on the
last `!`); managed `pe.pinvoke` is `Api from module` (the API name is the token
before `" from "`). The engine parses these two forms only.

## 5. Rule engine (`RunOrNope.Rules`)

### 5.1 Model

```csharp
public sealed record CapabilityRule(
    string Id,
    string Title,
    string PotentialImpact,
    RiskFamily Family,
    Severity Severity,
    EvidenceStatus EvidenceStatus,
    EvidenceConfidence EvidenceConfidence,
    RecommendedAction RecommendedAction,
    ImmutableArray<string> RequiredApis,   // matched case-insensitively
    int MinimumMatches,                    // N-of; AND when == RequiredApis.Length
    ImmutableArray<string> BenignExplanations);
```

### 5.2 Engine

`public static class CapabilityRuleEngine` with:

```csharp
public const string RulesVersion = "capability-rules-1";
public static ImmutableArray<CapabilityFinding> Evaluate(ImmutableArray<Observation> observations);
```

Behaviour:

- Build a lookup from each `pe.import` / `pe.pinvoke` observation to its extracted
  API name (case-insensitive). Ignore all other observation kinds.
- For each rule (in a fixed, declared order), collect the observation ids whose API
  name matches one of `RequiredApis`. Count **distinct matched APIs**; if that count
  `>= MinimumMatches`, emit one `CapabilityFinding`:
  - `Title`, `PotentialImpact`, `Family`, `Severity`, `EvidenceStatus`,
    `EvidenceConfidence`, `RecommendedAction`, `BenignExplanations` from the rule.
  - `ParserConfidence = High` (imports parse reliably).
  - `ApplicationLinkage = Unknown` (matches the root artifact; app/library
    attribution is a later slice).
  - `Reachability = Referenced`.
  - `ObservationIds` = the sorted, de-duplicated ids of the matched observations
    (at least one; satisfies the contract's provenance requirement).
  - `Limitations` = empty this slice.
- Deterministic output ordering (rule order, then observation-id order). No rule
  emits more than one finding per scan.

The engine depends only on `RunOrNope.Contracts`. It never parses sample bytes.

### 5.3 Curated first rule set (`CapabilityRuleSet.Default`)

Nine rules; each has strong benign explanations and honest tiers. AND unless noted.

| Id | Title | Family | Severity | Evidence | Required APIs (N-of) |
| --- | --- | --- | --- | --- | --- |
| process-injection | Injects code into another process | ProcessManipulation | High | StrongStructural | VirtualAllocEx + WriteProcessMemory + 1-of(CreateRemoteThread, NtCreateThreadEx, RtlCreateUserThread, QueueUserAPC) |
| token-manipulation | Manipulates process privileges/tokens | PrivilegeElevation | Medium | StrongStructural | OpenProcessToken + AdjustTokenPrivileges |
| dpapi-credential-access | Decrypts DPAPI-protected secrets | CredentialAccess | High | StrongStructural | CryptUnprotectData |
| screen-capture | Captures the screen | Surveillance | Medium | StrongStructural | BitBlt + CreateCompatibleBitmap |
| keylogging | Records keystrokes | Surveillance | High | StrongStructural | SetWindowsHookEx + 1-of(GetAsyncKeyState, GetKeyState, GetKeyboardState) |
| service-install | Installs a Windows service | Persistence | Medium | StrongStructural | OpenSCManager + CreateService |
| anti-debugging | Checks for a debugger | DefenseEvasion | Low | ApiOrLibraryPresenceOnly | 1-of(IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess) |
| dynamic-api-resolution | Resolves APIs at runtime | Obfuscation | Informational | ApiOrLibraryPresenceOnly | LoadLibrary + GetProcAddress |
| network-communication | Communicates over the network | NetworkCommunication | Low | ApiOrLibraryPresenceOnly | 1-of(InternetConnect, HttpSendRequest, WinHttpConnect, WSAConnect, connect, send) |

Notes: single-API and ubiquitous-pattern rules (anti-debugging, dynamic-api,
network) are intentionally weak (`ApiOrLibraryPresenceOnly`, low/informational
severity) so they contribute little to the verdict — they are context, not
accusations. `RecommendedAction` is `ExerciseCaution` for the structural rules and
`ReviewProvenance` for the weak ones; none uses `DoNotRunAndEscalate` in this slice.
API names match native imports and managed P/Invokes identically (e.g.
`CryptUnprotectData` appears both as a native import and as a P/Invoke).

## 6. `WorkerScan` assembly

After `PeScanResultMapper.Map` returns the structural result, run
`CapabilityRuleEngine.Evaluate(result.Observations)` and return
`result with { Findings = findings }`. `Unsupported`/`Malformed` results have no
observations, so they naturally yield no findings. The final result is still
serialized through `ScanContractJson` (which validates provenance and linkage).

## 7. Testing

- **Rule engine unit tests:** an injection cluster → one `process-injection` finding
  citing exactly the matched import observation ids; missing a required API → no
  finding; a weak single-API rule fires at `ApiOrLibraryPresenceOnly`; a managed
  P/Invoke (`CryptUnprotectData from crypt32.dll`) triggers `dpapi-credential-access`;
  deterministic ordering; findings validate against `ContractValidator`.
- **Mapper tests:** `pe.import` and `pe.pinvoke` observations emitted with the
  canonical descriptions; the 4096 cap forces `Incomplete` with a limitation.
- **End-to-end (`WorkerScan`):** a synthetic analysis whose imports form an injection
  cluster → a `ScanResult` whose findings drive `VerdictEngine` to
  `CautionWarranted`; a benign import set → `FewMaterialStaticConcerns`.
- All produced `ScanResult`s round-trip through `ScanContractJson`.

## 8. Files

- `src/RunOrNope.Rules/CapabilityRule.cs`, `CapabilityRuleSet.cs`,
  `CapabilityRuleEngine.cs` (new).
- `src/RunOrNope.Analyzers.Pe/PeScanResultMapper.cs` (emit `pe.import` / `pe.pinvoke`).
- `src/RunOrNope.Worker/WorkerScan.cs` (run the engine, assemble findings).
- `src/RunOrNope.Worker/RunOrNope.Worker.csproj` already references
  `RunOrNope.Rules`; the mapper/engine split keeps `Rules` decoupled from the PE
  analyzer.
- Tests under `tests/RunOrNope.UnitTests`.
