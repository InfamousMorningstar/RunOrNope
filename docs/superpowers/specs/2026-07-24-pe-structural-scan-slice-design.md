# PE Structural Scan Slice — Design

**Date:** July 24, 2026
**Status:** Approved design, pending written-spec review
**Parent design:** `docs/superpowers/specs/2026-07-24-run-or-nope-design.md`

## 1. Purpose

Wire the existing PE/CLR analyzer through the AppContainer worker so the full
pipeline — `intake → broker → isolated worker → evidence contract → verdict` —
runs end to end on real, honest data. Today the worker returns a placeholder
`ScanResult` ("analyzers are not installed yet"); `PeAnalyzer` produces a rich
`PeAnalysisResult` that nothing maps into the `ScanResult` contract the broker and
verdict engine consume. This slice closes that gap.

The slice is deliberately narrow: **structural observations only, no capability
findings**. It proves the transport and evidence plumbing without asserting any
risk disposition that a rules engine has not yet earned.

## 2. Scope

In scope:

- A deterministic mapper from `PeAnalysisResult` to `ScanResult`.
- Worker orchestration that runs `PeAnalyzer` inside the sandbox and returns a
  validated `ScanResult`.
- Unit tests for the mapper and the worker orchestration core.

Out of scope (each a separate later slice): capability findings, the rules engine,
MSI analysis, nested-artifact discovery, the WPF UI, broker changes, and a
through-the-sandbox end-to-end integration test.

## 3. Components

### 3.1 `PeScanResultMapper` (new, in `RunOrNope.Analyzers.Pe`)

A pure, deterministic static class. `RunOrNope.Analyzers.Pe` already references
`RunOrNope.Contracts`, so it is the natural, unit-testable home.

Signature:

```csharp
public static ScanResult Map(PeAnalysisResult analysis, string sha256, long size);
public static ScanResult Unsupported(string sha256, long size);
```

`Map` is used when the bytes parsed as a PE; `Unsupported` is used when the
in-worker byte check rejected the input, so the worker never needs a
`PeAnalysisResult` for a non-PE file.

Behaviour:

- Emits exactly one root `ArtifactNode`: `Id = "root"`, the worker-computed
  `sha256`, `size`, `ApplicationLinkage.Unknown`, no parents. Its `Completeness`
  matches the overall completeness the mapper selects.
- Emits **structural `Observation`s only** — never a `CapabilityFinding`. Every
  observation has a deterministic zero-padded id (`pe-obs-0001`, `pe-obs-0002`, …)
  in a stable emission order and a `SourceLocation` bound to `root`.
- `SampleName` is left empty. The submitted filename is sample-controlled metadata
  and is supplied by the UI from intake, never by the worker.

Observation kinds (each present only when applicable):

| Kind | Content |
| --- | --- |
| `pe.image` | PE32 vs PE32+, machine type |
| `pe.section` | Per section (bounded at 96): name, R/W/X characteristics, raw/virtual sizes |
| `pe.entry-point` | Entry RVA; whether mapped and in an executable section |
| `pe.anomaly` | One per `layout.StructuralAnomalies` entry |
| `pe.overlay` | Overlay offset and length, when length > 0 |
| `pe.certificate` | Certificate-table offset and length, when present |
| `pe.trust` | Authenticode disposition, native status, signature count, revocation-indeterminate flag |
| `pe.clr` | Managed flag; assembly name; assembly-reference, method, and unresolved-edge counts |
| `pe.rich-parser` | AsmResolver agreement; import/module/export counts |

All observation text is constructed from typed analyzer fields, not concatenated
sample strings, and stays within `ContractLimits.MaxStringLength`.

### 3.2 Status and completeness mapping

The mapper selects `AnalysisStatus` and `ArtifactCompleteness` honestly:

| Situation | AnalysisStatus | Completeness |
| --- | --- | --- |
| bytes are not a PE (`PeScanResultMapper.Unsupported`) | `UnsupportedOrInvalidRootFormat` | `Unsupported` |
| PE parsed; no `Limitations`; rich parser agreed; CLR analysis not truncated (`Clr.TruncatedByPolicy == false`); trust resolved (`Trusted`/`Untrusted`/`NoSignature`) | `Complete` | `Complete` |
| PE parsed but any `Limitations` present, or rich parser disagreed, or `Clr.TruncatedByPolicy == true`, or trust is `IndeterminateOffline` / `PlatformUnavailable` / `Malformed` | `Incomplete` | `TruncatedByPolicy` |

A truncated managed-metadata walk (method or per-method instruction limit reached) is
partial analysis: a rules engine reading the CLR call graph in a later slice could miss
capabilities that live in the unwalked methods. Treating `Clr.TruncatedByPolicy` as
`Complete` would let an attacker pad a managed binary past the walk limits and earn the
favorable zero-findings verdict — the exact "incompleteness becomes favorable" failure the
contract forbids. `Clr.UnresolvedEdges` (malformed method bodies) is surfaced in the
`pe.clr` observation for provenance; it does not by itself force `Incomplete` in this
structural slice, but the rules-engine slice must reconsider that once findings depend on
those edges.

This satisfies the contract invariants in `ContractValidator.ValidateCompleteness`:
a `Complete` result carries only a `Complete` root artifact; an `Incomplete`
result never carries `Complete` completeness.

### 3.3 CountervailingFacts and verdict interaction

The mapper adds exactly one countervailing fact, and only when the Authenticode
`Disposition == Trusted`: "Windows platform trust verified the embedded
signature." No other countervailing facts are produced in this slice.

The verdict is **not** computed inside the worker. `VerdictEngine.Evaluate` remains
in `RunOrNope.Core`, called outside the sandbox (broker/UI in a later slice). With
zero findings it yields `FewMaterialStaticConcerns` on a `Complete` scan and a
**null** disposition on an `Incomplete` scan — an incomplete scan can never read as
favorable. This behaviour is already implemented and unchanged.

### 3.4 Worker orchestration (`RunOrNope.Worker`)

Analysis logic moves into an internal, testable core:

```csharp
internal static ValueTask<ScanResult> WorkerScan.AnalyzeAsync(
    Stream sample, long size, string mode, CancellationToken cancellationToken);
```

exposed to the test project via `InternalsVisibleTo`. `Program.Main` remains the
thin handle/IPC adapter (parse args, open handles, read request, call
`WorkerScan`, write frame). `WorkerScan.AnalyzeAsync`:

1. Wraps the sample handle stream (read-only) — provided by `Program`.
2. Performs a lightweight in-sandbox `MZ` + `PE\0\0` byte check to decide supported
   vs unsupported. The broker's format claim is never trusted for parsing; support
   is re-derived from the bytes.
3. Computes SHA-256 over the sample stream (the worker already holds the bytes).
4. Runs `PeAnalyzer` with the real `WindowsAuthenticodeTrustBackend`. If WinTrust
   cannot operate inside the container the backend degrades to `PlatformUnavailable`
   (→ `Incomplete`); it must never crash the worker.
5. Calls `PeScanResultMapper.Map(...)`.
6. Wraps parsing exceptions (`PeFormatException` / `IOException`) into an
   `Incomplete` / `Malformed` `ScanResult`. No parser exception crosses the
   protocol boundary as a fault.

`mode` (`quick`/`deep`) is accepted and threaded but does not change behaviour in
this slice (no recursive discovery yet).

### 3.5 Broker

Unchanged. It already sends the `WorkerRequestEnvelope`, enforces the wall-clock
timeout, and validates the returned contract via `WorkerProtocol.ReadScanResultAsync`.

Follow-up (not this slice): cross-check the worker-returned root SHA-256 against
the hash intake computed over its owned handle, and fail closed on mismatch.

## 4. Data flow

```text
broker → WorkerRequestEnvelope (mode, sampleSize) ──▶ worker Program.Main
                                                        │ opens sample FileStream
                                                        ▼
                                              WorkerScan.AnalyzeAsync
                                                MZ/PE byte check
                                                SHA-256, PeAnalyzer
                                                        ▼
                                              PeScanResultMapper.Map
                                                        ▼
worker ◀── ScanResult (frame) ── WorkerProtocol.WriteFrameAsync
   │
   ▼ (broker validates)  →  VerdictEngine.Evaluate (Core, later slice, outside sandbox)
```

## 5. Error handling

- Non-PE bytes → `UnsupportedOrInvalidRootFormat` result (not an error).
- Parser rejection / malformed PE → `Incomplete` + `Malformed` result.
- WinTrust unavailable in container → trust `PlatformUnavailable` → `Incomplete`.
- Any unexpected `IOException`/`UnauthorizedAccessException` in `Program.Main`
  retains the existing nonzero exit-code behaviour; the broker maps a missing or
  malformed result to `IsolationUnavailable`.

## 6. Testing

- **`PeScanResultMapper` unit tests (primary):** clean native PE → `Complete` with
  the expected observation set; managed PE → a `pe.clr` observation; a
  trusted-signature analysis → the single countervailing fact; a forced limitation
  or offline-trust result → `Incomplete`; `isSupportedPe == false` → `Unsupported`.
  Every produced `ScanResult` is round-tripped through `ContractValidator.Validate`.
  Reuse the existing `PeFixture` builder.
- **`WorkerScan` unit tests (`InternalsVisibleTo`):** dispatch and exception mapping
  in-process, without the sandbox — supported PE stream, non-PE stream, and a
  truncated/malformed PE stream.
- Existing isolation/security suites continue to cover the transport and sandbox.
- A through-the-sandbox end-to-end test is a follow-up (requires the signed worker
  bundle harness) and is explicitly not part of this slice.

## 7. Non-goals

No capability findings, no rules engine, no MSI, no nested-artifact discovery, no
UI, no broker changes, no verdict changes. This slice only turns the existing PE
analyzer's output into a validated `ScanResult` produced inside the worker.
