# Task 4 Report — Read-Only MSI Native Boundary

## Outcome

Implemented the defensive, read-only Windows Installer database boundary and a
test-only writer for benign synthetic MSI fixtures. Production only inventories
fixed metadata queries and stream bytes; it does not create an installer session,
install, repair, apply transforms or patches, advertise, commit, persist, execute,
load, preview, contact, upload, or interpret sample-controlled values.

## Files

- `src/RunOrNope.Analyzers.Msi/MsiDatabase.cs`
- `src/RunOrNope.Analyzers.Msi/MsiTables.cs`
- `tests/RunOrNope.UnitTests/Msi/MsiFixtureBuilder.cs`
- `tests/RunOrNope.UnitTests/Msi/MsiDatabaseTests.cs`
- `tests/RunOrNope.SecurityTests/RunOrNope.SecurityTests.csproj`
- `tests/RunOrNope.SecurityTests/Msi/MsiNativeSurfaceTests.cs`
- `tests/RunOrNope.SecurityTests/Msi/MsiReadOnlyTests.cs`
- `tests/RunOrNope.SecurityTests/packages.lock.json` (mechanically regenerated
  project-reference entry only)
- `.superpowers/sdd/2026-07-30-msi-analysis-implementation/task-4-report.md`

## TDD Evidence

Tests and the fixture writer were added before either production file existed.

The first restore RED was the expected locked-restore stop:

```text
NU1004: A new project reference to RunOrNope.Analyzers.Msi was found ...
The packages lock file is inconsistent with the project dependencies
```

After mechanically regenerating only the security project lockfile, the first test
invocation exposed a test-scaffolding error (missing explicit `Xunit` imports). That
was corrected without production changes. The ensuing unit RED was the intended
missing-feature failure:

```text
MsiDatabaseTests.cs: error CS0103: The name 'MsiDatabase' does not exist
MsiDatabaseTests.cs: error CS0103: The name 'MsiTables' does not exist
MsiDatabaseTests.cs: error CS0246: MsiRecordValue could not be found
```

The metadata/security RED likewise contained the intended missing production type:

```text
MsiNativeSurfaceTests.cs: error CS0246: The type or namespace name
'MsiDatabase' could not be found
```

That security compile also exposed two guard-implementation issues
(`MetadataReader.ModuleReferences` and an assertion expression); those test-only
issues were corrected during GREEN. No production behavior was weakened to make a
guard pass.

Focused GREEN:

```text
MsiDatabaseTests: 7 passed, 0 failed, 0 skipped
MsiNativeSurfaceTests + MsiReadOnlyTests: 7 passed, 0 failed, 0 skipped
```

## Native Surface and Negative-Guard Review

- Compiled production module references equal exactly `{ "msi.dll" }`.
- Compiled imports equal exactly this read-only set:
  `MsiOpenDatabaseW`, `MsiDatabaseOpenViewW`, `MsiViewExecute`,
  `MsiViewFetch`, `MsiViewClose`, `MsiRecordGetFieldCount`,
  `MsiRecordIsNull`, `MsiRecordGetInteger`, `MsiRecordGetStringW`,
  `MsiRecordDataSize`, `MsiRecordReadStream`,
  `MsiGetSummaryInformationW`, `MsiSummaryInfoGetPropertyW`, and
  `MsiCloseHandle`.
- Exact native signatures, Unicode/Winapi attributes, and parameter widths are
  asserted from compiled metadata/reflection.
- Decoded IL rejects `calli`; unmanaged function-pointer signatures; and references
  to `NativeLibrary`, `GetProcAddress*`, `LoadLibrary*`, or
  `GetDelegateForFunctionPointer*`.
- Every compiled `MsiOpenDatabaseW` call site is counted. The sole call is in
  `OpenNativeReadOnly`, and its compiler-adjacent IL supplies `ldc.i4.0` followed by
  `conv.i` for null/read-only persistence.
- Exact import-set equality excludes all mutating APIs. A separate negative list
  explicitly rejects create, commit, record setters, summary persistence,
  view-modify, package/product session, install/configure, transform, patch, and
  advertise APIs.
- All production SQL text is confined to fixed internal `MsiTables` definitions.
  There is no public SQL-taking API.
- Mutating imports exist only in `MsiFixtureBuilder`, linked into test assemblies.
  Fixture content and values are test-authored benign literals.

## Bounds, Completeness, and Handle Proof

- Native strings use a two-call measurement/read sequence, cap allocation before
  allocation, pass retrieved text through `MsiTextPolicy`, and explicitly mark
  policy truncation, growth, and shortening incomplete.
- Stream reads use a fixed 64 KiB buffer and charge the actual returned byte count
  to an existing `ExtractionBudget`; the focused proof charges exactly 70,001 bytes.
- Native failures are translated with the exact status and are never reported as an
  absent/complete inventory. Cancellation propagates.
- Database, view, record, and summary resources use owning safe handles. Compiled IL
  asserts each owner closes exactly its handle, while views call `MsiViewClose`
  before `MsiCloseHandle`.
- Runtime tests exercise success and injected mapper failure. After disposal, the
  MSI can be reopened with `FileShare.None`.
- The read-only proof hashes a fixture before analysis, inventories it, disposes all
  native owners, reopens it exclusively, and verifies the SHA-256 is unchanged.

## Verification

Pinned SDK commands:

```text
restore --locked-mode: passed
Release build: passed, 0 warnings, 0 errors
Focused unit: 7 passed
Focused security: 7 passed
Full unit project: 350 passed, 0 skipped
Full security project: 66 passed, 0 skipped
Full integration project: 7 passed, 0 skipped
git diff --check: exit 0
```

Total full suite at verification: 423 passed, 0 failed, 0 skipped.

## Concerns

No known correctness or security blocker. The fixture-table definitions are
deliberately internal and temporary test coverage points; later MSI analyzer slices
should add their standard-table definitions to `MsiTables` rather than accepting
caller-provided SQL.
