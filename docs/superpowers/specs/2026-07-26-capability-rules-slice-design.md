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
after the last `" from "` — the entry-point name is attacker-controlled metadata, so
a name embedding the separator must degrade to a non-match rather than impersonate
the API it prefixes). The engine parses these two forms only.

### 4.1 Import visibility

Rules can only cite imports whose names are readable, so an image that exposes none
produces no findings — and "no findings" would otherwise score as the most favourable
disposition available. That inverts the project's core rule that absence of evidence
never becomes a favourable result: a packed sample resolving everything through
`GetProcAddress`, or one importing purely by ordinal (rendered `module!#42`, which no
rule can match), would read as clean precisely *because* it hid its imports.

The mapper therefore emits a `pe.import-visibility` observation and forces
`Incomplete` when the readable import inventory cannot support the analysis:

- no readable import names at all, or
- ordinal-only symbols at least equalling the readable ones.

`VerdictEngine` already returns a `null` disposition for an `Incomplete` scan whose
candidate is `FewMaterialStaticConcerns`, so this withholds the verdict rather than
inventing a bad one. No accusation is made — an opaque import table is a fact about
what the checks could see, not evidence of intent.

Three exemptions, each because import poverty is expected rather than evasive:

- **Managed assemblies** (`clr.IsManaged`): the native import table is a runtime stub
  and the evidence path is `pe.pinvoke`.
- **Resource-only images** (`EntryPointRva == 0`): no code, so nothing to hide.
- **Analyses that already carry a limitation**: the incompleteness is already
  recorded, and a visibility claim would describe an inventory never collected.

The ordinal-dominance threshold is deliberately blunt. It will mark some legitimate
ordinal-heavy binaries (MFC being the classic case) `Incomplete`, which is the
intended trade: withholding a verdict on a file whose import surface is half opaque
is honest, and the observation says exactly why.

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
    ImmutableArray<string> RequiredAllApis,  // every one must be present
    ImmutableArray<string> AnyOfApis,        // at least one must also be present
    ImmutableArray<string> BenignExplanations);
```

**Superseded:** an earlier draft of this section used `RequiredApis` plus an
`int MinimumMatches` ("N-of") counter. That model could not express the rule table
in §5.3 and overmatched badly in practice — `process-injection` at 3-of-6 fired on
`WriteProcessMemory` + `CreateRemoteThread` + `QueueUserAPC` with no allocation at
all, and `keylogging` at 2-of-4 fired on `GetAsyncKeyState` + `GetKeyState`, which
is what every game and hotkey handler imports. The required-core-plus-any-of shape
above expresses the intended table directly. Both overmatches are locked out by
regression tests.

### 5.2 Engine

`public static class CapabilityRuleEngine` with:

```csharp
public const string RulesVersion = "capability-rules-1";
public static ImmutableArray<CapabilityFinding> Evaluate(ImmutableArray<Observation> observations);
```

Behaviour:

- Build a lookup from each `pe.import` / `pe.pinvoke` observation to its extracted
  API name (case-insensitive). Ignore all other observation kinds.
- For each rule (in a fixed, declared order), a match requires **every** API in
  `RequiredAllApis` to be present and, when `AnyOfApis` is non-empty, **at least one**
  of those to be present as well. Either array may be empty: an empty core with a
  non-empty any-of is the "1-of" shape used by the weak rules; an empty any-of with a
  non-empty core is a pure AND. A rule with both empty never fires. Every matched
  API's observation ids are collected — including all present alternatives, so a
  finding cites all of its support, not just the first match. On a match, emit one
  `CapabilityFinding`:
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

Nine rules; each has strong benign explanations and honest tiers.

| Id | Title | Family | Severity | Evidence | Required core | Any-of |
| --- | --- | --- | --- | --- | --- | --- |
| process-injection | Injects code into another process | ProcessManipulation | High | StrongStructural | VirtualAllocEx + WriteProcessMemory | CreateRemoteThread, CreateRemoteThreadEx, NtCreateThreadEx, RtlCreateUserThread, QueueUserAPC, QueueUserAPC2 |
| token-manipulation | Manipulates process privileges/tokens | PrivilegeElevation | Medium | StrongStructural | OpenProcessToken + AdjustTokenPrivileges | — |
| dpapi-credential-access | Decrypts DPAPI-protected secrets | CredentialAccess | High | StrongStructural | CryptUnprotectData | — |
| screen-capture | Captures the screen | Surveillance | Medium | StrongStructural | BitBlt + CreateCompatibleBitmap | GetDesktopWindow, GetWindowDC, GetDC |
| keylogging | Records keystrokes | Surveillance | High | StrongStructural | SetWindowsHookEx | GetAsyncKeyState, GetKeyState, GetKeyboardState |
| service-install | Installs a Windows service | Persistence | Medium | StrongStructural | OpenSCManager + CreateService | — |
| anti-debugging | Checks for a debugger | DefenseEvasion | Informational | ApiOrLibraryPresenceOnly | — | IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, ZwQueryInformationProcess |
| dynamic-api-resolution | Resolves APIs at runtime | Obfuscation | Informational | ApiOrLibraryPresenceOnly | GetProcAddress | LoadLibrary, LoadLibraryEx |
| network-communication | Communicates over the network | NetworkCommunication | Informational | ApiOrLibraryPresenceOnly | — | InternetConnect, HttpSendRequest, WinHttpConnect, WSAConnect, connect |

Notes: single-API and ubiquitous-pattern rules (anti-debugging, dynamic-api,
network) are intentionally weak (`ApiOrLibraryPresenceOnly`, informational severity)
so they contribute little to the verdict — they are context, not accusations.
`RecommendedAction` is `ExerciseCaution` for the structural rules and
`ReviewProvenance` for the weak ones; none uses `DoNotRunAndEscalate` in this slice.
API names match native imports and managed P/Invokes identically (e.g.
`CryptUnprotectData` appears both as a native import and as a P/Invoke).

Name matching expands each entry to its ANSI/Wide variants (`X`, `XA`, `XW`), which
covers charset pairs only. Distinct exports that merely share a prefix — the `Ex`
and `2` suffixes, and ntdll's `Zw` aliases — must be listed by name; that is why
`CreateRemoteThreadEx`, `QueueUserAPC2`, `LoadLibraryEx`, and
`ZwQueryInformationProcess` appear explicitly above.

Three tier changes from the first draft of this table, all made to keep ordinary
software out of `CautionWarranted` without touching `ScoringPolicy`:

- **`anti-debugging` and `network-communication` drop from `Low` to
  `Informational`.** At `Low` each scored 8 against a `CautionThreshold` of 15, so a
  program that checks for a debugger (the CRT does this on assert paths) and opens a
  socket scored 16 and was flagged on presence alone. All presence-only rules now
  score 4, totalling 12 when all three fire.
- **`screen-capture` gains a required device-context any-of.** `BitBlt` +
  `CreateCompatibleBitmap` alone is the standard double-buffered painting idiom used
  by every custom-drawn control, and at 25 points it flipped benign charting and
  printing code to `CautionWarranted` on its own.
- **`dynamic-api-resolution` is keyed on `GetProcAddress` with an any-of loader
  set** rather than `LoadLibrary + GetProcAddress`, so `LoadLibraryEx`-only callers
  are still matched.

`send` was dropped from `network-communication`: anything reaching it already
connected through one of the other entries, so it added no detection value while
widening the surface for a same-named managed P/Invoke to match.

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
- **Import visibility (§4.1):** a native image with no readable imports, and one whose
  imports are ordinal-dominated, each force `Incomplete` with a
  `pe.import-visibility` observation; a readable import set, a resource-only image,
  and a managed assembly each stay `Complete`. End-to-end, a packed sample with no
  readable imports must yield a `null` disposition — never
  `FewMaterialStaticConcerns`.
- **Overmatch regressions:** the two shapes the superseded N-of model got wrong —
  an injection cluster missing `VirtualAllocEx`, and key-state polling with no hook —
  must produce no finding. A required core with no satisfied alternative
  (`VirtualAllocEx` + `WriteProcessMemory` alone) and half of a pure AND
  (`OpenSCManager` alone) must likewise stay silent.
- **Name matching:** an `Ex`-suffixed export (`CreateRemoteThreadEx`), a `Zw` alias,
  and a `LoadLibraryExW`-only resolver must each match; the same API imported from two
  modules yields one finding citing both observation ids; a P/Invoke entry-point name
  that embeds the `" from "` separator must not impersonate a targeted API.
- **End-to-end (`WorkerScan`):** a synthetic analysis whose imports form an injection
  cluster → a `ScanResult` whose findings drive `VerdictEngine` to
  `CautionWarranted`; a benign import set → `FewMaterialStaticConcerns`. A realistic
  ordinary-desktop-app import set that fires *every* presence-only rule must still
  reach `FewMaterialStaticConcerns` — this is the guard on the tier calibration
  described in §5.3.
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
