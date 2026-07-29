# Artifact Graph Slice — Design

**Date:** July 29, 2026
**Status:** Draft, pending review
**Parent design:** `docs/superpowers/specs/2026-07-24-run-or-nope-design.md`
**Plan task:** 6 (Artifact Graph, Strings, and Safe Nested Content)

## 1. Purpose

Give the analyzer a bounded, deduplicated graph of the artifacts nested inside a
sample, and the budget and path policy that make walking attacker-authored
containers safe. Everything downstream — strings, container readers, MSI, and
capability rules over nested code — hangs off this graph, so it is built first and
on its own.

## 2. Task 6 is three slices

Task 6 as written covers six source files and two test projects. It splits along
clean seams, and this design covers only the first:

| Slice | Delivers | Files |
| --- | --- | --- |
| **6a (this)** | Budget, path policy, artifact DAG | `ExtractionBudget`, `ArchivePathPolicy`, `ArtifactGraphBuilder` |
| 6b | Strings with provenance | `StringExtractor` |
| 6c | Bounded container readers | `AsarReader`, `JarClassReader` |

6a produces no format readers. It is exercised through a test-only container
provider, so the safety properties are locked before any real parser exists to
argue with. 6b and 6c then plug into a graph whose accounting is already proven.

## 3. Contract constraints that shape this slice

Three properties of the existing contract are load-bearing here. They were read out
of `ContractValidator`, not assumed.

**3.1 A complete analysis cannot contain an incomplete artifact.**
`ValidateCompleteness` rejects a `ScanResult` whose status is `Complete` while any
artifact is not `Complete`. This is the fail-closed rule already enforced at the
boundary: the moment the budget truncates one nested entry, the whole scan must
report `Incomplete`. The builder does not get to decide this — it computes the scan
status *from* the artifact set, and the validator is the backstop.

**3.2 A finding's evidence must bind to exactly one artifact.**
`ValidateEvidenceReferences` throws if a finding cites observations sourced to two
different artifacts, and separately requires `finding.ApplicationLinkage` to equal
the cited artifact's linkage. See §4 — this is a blocking prerequisite, not a note.

**3.3 The ceilings are contractual.**
`MaxArtifacts` is 4096 and `MaxObservations` is 65,536. Exceeding either throws at
the boundary, so the budget's own ceilings must sit at or below them and truncation
must be a completeness event rather than an exception.

## 4. Blocking prerequisite: the rules engine is single-artifact

`CapabilityRuleEngine.Evaluate` builds one API lookup across *every* observation in
the result, with no regard for which artifact each came from, and emits findings
hardcoded to `ApplicationLinkage.Unknown`. That is correct today only because there
is exactly one artifact — the root.

The first nested PE this slice discovers breaks it. An injection cluster split
across the root and a bundled DLL would produce a finding citing observations from
two artifacts, and `ValidateEvidenceReferences` would throw
`"A finding's evidence must bind to one source artifact"` — turning a scan into a
crash. Worse, a cluster assembled from *unrelated* binaries would be a false
accusation even if the contract allowed it: a launcher that allocates and a plugin
that spawns threads are not an injector.

The fix lands with this slice, before any nested artifact is emitted:

- `Evaluate` groups observations by `Source.ArtifactId` and runs the rule set once
  per artifact, so a finding is always assembled from a single artifact's evidence.
- Each finding takes its `ApplicationLinkage` from the artifact it was matched
  against, satisfying the validator's linkage check.
- Output order becomes artifact order, then rule order, then observation-id order.
  The existing determinism test extends to cover the artifact dimension.

A root-only scan produces byte-identical output to today, so this is a safe
generalisation rather than a behaviour change. Existing rule tests stay green.

## 5. `ExtractionBudget`

An immutable set of ceilings plus a mutable accounting state threaded through the
walk. Every ceiling is a hard stop that yields `TruncatedByPolicy`; none throws.

| Ceiling | Value | Why |
| --- | --- | --- |
| `MaxDepth` | 8 | Nesting past this is packaging pathology, not structure. |
| `MaxArtifacts` | 2048 | Half the contract's 4096, leaving headroom for MSI's own nodes. |
| `MaxTotalExpandedBytes` | 1 GiB | The decompression-bomb stop. |
| `MaxArtifactBytes` | 256 MiB | One entry cannot consume the whole budget. |
| `MaxEntriesPerContainer` | 16,384 | Bounds a container whose directory claims millions of entries. |
| `MaxExpansionRatio` | 200:1 | Tripwire for a single hugely compressible entry. |

Two accounting rules carry the security weight:

**Count before you trust.** Declared sizes in a container directory are
attacker-controlled. The budget is charged against *bytes actually read*, streamed
and checked incrementally, so an entry declaring 4 GiB stops at the ceiling rather
than at its own claim. A declared size that disagrees with the bytes delivered is
itself an observation.

**Count deduplicated entries too.** Identity dedup is an analysis optimisation, not
an accounting one. A container holding 10,000 copies of the same 1 MiB file creates
one artifact node but charges 10,000 entries and 10 GiB against the budget.
Charging only the deduplicated bytes would hand an attacker a free unbounded
expansion by simply repeating a payload — the exact trick dedup appears to defend
against.

No disk reserve check is specified, because §6 removes the need for one in the
common path.

## 6. `ArchivePathPolicy`

The invariant this slice establishes, and the reason the traversal surface is
small: **a sample-controlled string is never passed to a filesystem API.**

Artifacts are analyzed from memory. An artifact exceeding an in-memory threshold
(16 MiB) spills to the worker's private AppContainer directory under a *generated
opaque name* — `art-0007.bin`, derived from the artifact's own index and nothing
else. Entry names from the container never reach `Path.Combine`, never influence a
file location, and never determine an extension.

`ArchivePathPolicy` therefore governs **display and identity only**. It classifies
each entry name and returns a safe display form plus a reason when the name is
hostile, so the report can say *what the container claimed* without ever having
acted on it:

- Traversal segments (`..`), absolute and rooted paths, drive letters, UNC prefixes.
- Reserved DOS device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`),
  with and without extensions.
- Alternate-data-stream colons, null bytes, trailing dots and spaces.
- Separator confusion (`/` vs `\`) and case-insensitive collisions between entries.
- Names exceeding the contract's string ceiling, and bidi controls — routed through
  the same neutralisation the PE mapper's `CleanText` already applies.

A hostile name is not a rejection of the *content*: the bytes are still analyzed
under a generated name, and the claimed name is reported as an observation. Refusing
to look at a payload because its name was ugly would be exactly the favourable-on-
absence failure the project forbids.

## 7. `ArtifactGraphBuilder`

**A DAG, not a tree.** Nodes are identified by SHA-256, so the same bytes reached by
two paths are one node carrying both `ParentIds`. This is why `ArtifactNode` already
has a `ParentIds` array rather than a single parent.

**Cycles terminate by construction.** A container that embeds itself hashes to a node
that already exists; the builder adds the parent edge and does not recurse. The depth
ceiling is the backstop, not the primary defence.

**Deterministic identity.** Artifacts are numbered `art-0001` upward in discovery
order (breadth-first, entry order within a container); the root keeps
`ScanArtifacts.RootId`. Identical input always yields identical ids.

**Observation ids become artifact-scoped.** Today `PeScanResultMapper` issues
`pe-obs-NNNN` from a private counter, which is unique only because there is one
artifact. Ids become `{artifactId}-obs-{NNNN}` — `root-obs-0001`,
`art-0003-obs-0001`. Uniqueness is then structural rather than incidental, and an
id names its own provenance, which makes the §3.2 single-artifact rule visible in
the report instead of buried in the validator. This renames existing root
observations; the PE mapper tests update with it.

**Completeness propagates upward.** A truncated, encrypted, malformed, or unsupported
child marks its own node and forces the scan to `Incomplete`. A container the walk
could not fully enumerate is `TruncatedByPolicy` even when every artifact it *did*
yield parsed cleanly — the honest claim is about what was seen, not what parsed.

Observations emitted by this slice, all sourced to the *containing* artifact so a
rejected entry that never became a node still has somewhere to hang:

| Kind | Emitted when |
| --- | --- |
| `artifact.nested` | A child artifact is added, naming its safe display name and size. |
| `artifact.duplicate` | Content already seen elsewhere in the graph; names both paths. |
| `artifact.hostile-name` | The claimed entry name violated the path policy, with the reason. |
| `artifact.size-mismatch` | Declared size disagreed with bytes delivered. |
| `artifact.truncated` | A ceiling stopped the walk, naming which one. |

## 8. Testing

Traversal and naming, each asserting the bytes were still analyzed under a generated
name and no filesystem path was influenced:

- `../../evil.dll`, `..\..\evil.dll`, and a deep `a/../../..` chain.
- `C:\Windows\System32\evil.dll`, `/etc/passwd`, `\\server\share\evil.dll`.
- `CON`, `NUL.txt`, `COM1`, `LPT9.dll`.
- `file.txt:hidden`, an embedded null byte, a trailing dot and trailing space.
- Two entries differing only in case; two differing only in separator.
- A name exceeding `MaxStringLength`, and one carrying a bidi override.

Budget and bombs:

- Ten thousand identical entries: **one** artifact node, but entries and expanded
  bytes charged ten thousand times, and the scan is `Incomplete`.
- An entry declaring 4 GiB that delivers 1 KiB, and one declaring 1 KiB that
  delivers 4 GiB — both stop at a ceiling and emit `artifact.size-mismatch`.
- A single entry exceeding `MaxExpansionRatio`.
- Nesting past `MaxDepth`, and a container exceeding `MaxEntriesPerContainer`.
- Each ceiling independently produces `TruncatedByPolicy` and never an exception.
- Artifact count is capped below the contract's `MaxArtifacts`, so a graph at the
  budget ceiling still validates.

Graph shape:

- The same payload reachable by two paths: one node, two `ParentIds`.
- A container embedding its own bytes terminates, with the cycle edge recorded.
- Ids are stable across repeated runs over the same input.
- Every emitted graph passes `ContractValidator.Validate` and round-trips through
  `ScanContractJson`.

Rules-engine generalisation (§4):

- A root-only scan produces output identical to the pre-change engine.
- An injection cluster split across two artifacts produces **no** finding, rather
  than a validation exception or a false accusation.
- A cluster wholly inside one nested artifact produces a finding whose
  `ApplicationLinkage` matches that artifact's.
- Determinism holds across artifact, rule, and observation-id order.

Fail-closed end to end:

- A scan whose only nested artifact was truncated reports `Incomplete` and a `null`
  disposition — never `FewMaterialStaticConcerns`.

## 9. Files

- `src/RunOrNope.Analyzers.Content/ExtractionBudget.cs`, `ArchivePathPolicy.cs`,
  `ArtifactGraphBuilder.cs` (new).
- `src/RunOrNope.Rules/CapabilityRuleEngine.cs` (per-artifact evaluation, §4).
- `src/RunOrNope.Analyzers.Pe/PeScanResultMapper.cs` (artifact-scoped observation
  ids, §7).
- `tests/RunOrNope.UnitTests/Content/`, `tests/RunOrNope.SecurityTests/Extraction/`.
