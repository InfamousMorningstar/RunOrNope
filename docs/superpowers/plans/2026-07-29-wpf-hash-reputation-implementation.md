# WPF Experience and Hash Reputation Implementation Plan

> **Execution:** Inline in the delivery worktree. Follow red-green-refactor for
> every production behavior and verify the full pinned-SDK suite before commit.

**Goal:** Build the Task 10 WPF workflow, safe report export, and explicit
SHA-256-only VirusTotal lookup while keeping credentials and reputation outside the
worker, reports, and verdict scoring.

**Architecture:** `MainViewModel` coordinates narrow App-layer services.
`ScanCoordinator` composes safe intake with `IWorkerBroker`; capability card view
models project validated evidence; `VirusTotalHashLookup` owns the fixed, bounded
HTTP protocol. WPF code-behind is limited to OS dialogs, drag/drop, and bridging
`PasswordBox.PasswordChanged`.

**Tech stack:** .NET 10/C# 14, WPF, `HttpClient`, `System.Text.Json`, xUnit,
AwesomeAssertions. No new package.

**Known external blocker:** real broker/worker analysis currently truncates its
response frame and maps to `IsolationUnavailable`. Do not change broker/worker code.
Coordinator integration uses `IWorkerBroker` fakes until the parsing lane lands its
fix.

---

### Task 1: App service contracts and scan coordinator

**Files:**

- Create: `src/RunOrNope.App/Services/AppServiceContracts.cs`
- Create: `src/RunOrNope.App/Services/ScanCoordinator.cs`
- Create: `tests/RunOrNope.UnitTests/App/ScanCoordinatorTests.cs`
- Modify: `tests/RunOrNope.UnitTests/RunOrNope.UnitTests.csproj`

**Interfaces:**

- Consumes: `SafeFileIntake.OpenAsync`, `IWorkerBroker.AnalyzeAsync(SafeFileLease,
  ScanRequest, CancellationToken)`, `WorkerResultIntegrity`, `VerdictEngine`.
- Produces: `IScanCoordinator.ScanAsync(string, ScanMode, CancellationToken)` and
  `CompletedScan`.

- [ ] Write a failing test using a fake `IWorkerBroker` that records the lease and
  request, returns a synthetic validated result, and asserts:

```csharp
completed.Sha256.Should().Be(ExpectedSha256);
broker.Request.Should().Be(new ScanRequest(string.Empty, ScanMode.Deep));
broker.Lease.Should().NotBeNull();
completed.Verdict.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
```

- [ ] Add failing cases for empty path, broker result identity mismatch,
  `IsolationUnavailable`, cancellation, and lease disposal on every exit.
- [ ] Implement `ISafeFileIntake` as an App seam whose production implementation
  forwards to `SafeFileIntake.OpenAsync`; implement coordinator ownership with
  `using var lease`, an empty worker path, root identity verification, and verdict
  evaluation.
- [ ] Run:

```powershell
& .\.tools\dotnet\dotnet.exe test tests\RunOrNope.UnitTests -c Release --filter "ScanCoordinator"
```

Expected: all coordinator tests pass without invoking the real worker.

---

### Task 2: VirusTotal bounded hash protocol

**Files:**

- Create: `src/RunOrNope.App/Services/VirusTotalHashLookup.cs`
- Create: `tests/RunOrNope.UnitTests/App/VirusTotalHashLookupTests.cs`

**Interfaces:**

- Consumes: fixed `HttpClient` with redirects/cookies/decompression disabled.
- Produces: `IHashReputationLookup.LookupAsync(string sha256, string apiKey,
  CancellationToken)` and bounded `HashReputationResult`.

- [ ] Write failing tests with an in-memory `HttpMessageHandler`. The primary test
  asserts exact request shape:

```csharp
request.Method.Should().Be(HttpMethod.Get);
request.RequestUri.Should().Be(
    $"https://www.virustotal.com/api/v3/files/{ExpectedSha256}");
request.RequestUri!.Query.Should().BeEmpty();
request.Headers.GetValues("x-apikey").Should().Equal("session-key");
request.Content.Should().BeNull();
```

- [ ] Add failing tests for invalid SHA-256, empty/CR/LF key, mismatched `data.id`,
  missing/negative/overflow stats, invalid date, malformed/deep JSON, declared and
  streamed bodies above 1 MiB, redirects, 404, 401/403, 429, transient statuses,
  other failures, timeout, cancellation, and network errors.
- [ ] Implement per-request header authentication, `ResponseHeadersRead`, a 1 MiB
  counting stream, JSON maximum depth 32, exact id validation, non-negative count
  parsing, fixed status mapping, and fixed credential-free errors.
- [ ] Expose `VirusTotalHashLookup.CreateHttpClient()` for production construction
  and internal handler-policy testing; set `AllowAutoRedirect=false`,
  `UseCookies=false`, `AutomaticDecompression=None`, fixed base URI, and 15-second
  timeout.
- [ ] Run:

```powershell
& .\.tools\dotnet\dotnet.exe test tests\RunOrNope.UnitTests -c Release --filter "VirusTotalHashLookup"
```

Expected: all HTTP tests pass with zero real network access.

---

### Task 3: Report export and capability projections

**Files:**

- Create: `src/RunOrNope.App/Services/ReportExportService.cs`
- Create: `src/RunOrNope.App/ViewModels/CapabilityCardViewModel.cs`
- Create: `src/RunOrNope.App/ViewModels/HashReputationViewModel.cs`
- Create: `tests/RunOrNope.UnitTests/App/CapabilityCardViewModelTests.cs`
- Create: `tests/RunOrNope.UnitTests/App/ReportExportServiceTests.cs`

**Interfaces:**

- Consumes: Task 9 HTML/JSON writers and validated `ScanResult`.
- Produces: `IReportExportService.ExportAsync`, `CapabilityCardViewModel.From`,
  and display-only reputation state.

- [ ] Write failing card tests proving presence-only/Informational differs from
  strong-structural/High and every evidence/source field is retained, including
  `Not reported` for nullable offset/region.
- [ ] Write failing export tests proving redacted default/full selection, safe
  suggested names, exact destination writes, cancellation, fixed errors, and no
  preview/shell-open operation.
- [ ] Implement immutable card projection by resolving cited observations and
  artifacts from the validated result; never create URIs or commands from dynamic
  text.
- [ ] Implement export bytes through Task 9 and asynchronous `FileStream` writes to
  the already user-confirmed path.
- [ ] Run:

```powershell
& .\.tools\dotnet\dotnet.exe test tests\RunOrNope.UnitTests -c Release --filter "CapabilityCard|ReportExport"
```

---

### Task 4: Main view-model state machine and credential containment

**Files:**

- Create: `src/RunOrNope.App/Infrastructure/AsyncCommand.cs`
- Create: `src/RunOrNope.App/Infrastructure/UiDispatcher.cs`
- Create: `src/RunOrNope.App/ViewModels/MainViewModel.cs`
- Create: `tests/RunOrNope.UnitTests/App/MainViewModelTests.cs`

**Interfaces:**

- Consumes: `IScanCoordinator`, `IReportExportService`,
  `IHashReputationLookup`, `IUserInteraction`.
- Produces: commands and properties documented in the Task 10 design.

- [ ] Write failing state-transition tests for successful Quick/Deep scans,
  cancellation, fixed failure messages, incomplete-withheld disposition,
  high-risk-plus-incomplete, stale completion, second-start denial, rescan cleanup,
  and disposal.
- [ ] Write failing confirmation tests: cancelled confirmation sends zero requests;
  every lookup reconfirms with exact hash and fixed destination; skipped/failed/
  clean-looking/malicious results never mutate the captured static verdict.
- [ ] Write failing credential tests proving the key is private/non-bindable,
  retained across scans, replaceable, clearable, absent from every DTO/message/
  exception/report argument, and dereferenced on disposal. Assert no
  `SecureString` field/property/type appears in the App assembly.
- [ ] Implement a generation-guarded single-operation state machine, cancellation
  ownership, fixed user messages, command requery, memory-only private key field,
  and separate reputation state.
- [ ] Run:

```powershell
& .\.tools\dotnet\dotnet.exe test tests\RunOrNope.UnitTests -c Release --filter "MainViewModel"
```

---

### Task 5: Accessible WPF shell and capability cards

**Files:**

- Create: `src/RunOrNope.App/App.xaml`
- Create: `src/RunOrNope.App/App.xaml.cs`
- Create: `src/RunOrNope.App/MainWindow.xaml`
- Create: `src/RunOrNope.App/MainWindow.xaml.cs`
- Create: `src/RunOrNope.App/Views/CapabilityCard.xaml`
- Create: `src/RunOrNope.App/Views/CapabilityCard.xaml.cs`
- Create: `tests/RunOrNope.UnitTests/App/WpfShellTests.cs`

**Interfaces:**

- Consumes: `MainViewModel`.
- Produces: browse/drop/scan/cancel/export/lookup desktop interaction.

- [ ] Write failing XAML/runtime tests for persistent safety copy, PasswordBox
  (never TextBox) credential entry, automation names/live status, keyboard
  gestures, virtualized findings, independent completeness/disposition labels,
  evidence-tier labels, and absence of navigation/sample-open controls.
- [ ] Implement the fixed WPF visual hierarchy with system/high-contrast-aware
  brushes, text-plus-color states, minimum primary target sizes, access keys, and
  logical tab order.
- [ ] Limit code-behind to browse/save dialogs, file-drop shape validation,
  `PasswordChanged` → `SetVirusTotalApiKey`, and disposal. Do not bind or expose the
  key as a property.
- [ ] Implement capability card bindings for every tier/provenance field and
  bounded lists of explanations/limitations.
- [ ] Run:

```powershell
& .\.tools\dotnet\dotnet.exe test tests\RunOrNope.UnitTests -c Release --filter "WpfShell|CapabilityCard"
```

---

### Task 6: Fake-broker workflow integration, review, and commit

**Files:**

- Create: `tests/RunOrNope.IntegrationTests/App/ScanWorkflowTests.cs`
- Modify: `tests/RunOrNope.IntegrationTests/RunOrNope.IntegrationTests.csproj`
- Update: `.remember/2026-07-29-task-10-wpf.md`

**Interfaces:**

- Consumes: all Task 10 App services through fakes/local handlers.
- Produces: verified Task 10 slice without claiming the blocked real worker path.

- [ ] Add integration tests for one-open intake → fake broker → validated result →
  verdict/cards → report export, and for intake rejection, cancellation,
  `IsolationUnavailable`, and reputation independence.
- [ ] Assert the fake broker receives the lease and empty request path; no App code
  reopens the sample or contacts a real network endpoint.
- [ ] Self-review the diff against every requirement in the approved design. Check
  App has no analyzer reference, no credential persistence or `SecureString`, no
  sample execution/preview/shell-open code, and no broker/worker modifications.
- [ ] Run fresh verification:

```powershell
& .\.tools\dotnet\dotnet.exe restore --locked-mode
& .\.tools\dotnet\dotnet.exe build -c Release --no-restore
& .\.tools\dotnet\dotnet.exe test -c Release --no-build
```

Expected: all non-skipped tests pass; the pre-existing skipped
`HandleChainTests.Analysis_DoesNotDisposeTheCallersLease` remains documented.

- [ ] Commit:

```powershell
git add src/RunOrNope.App tests/RunOrNope.UnitTests/App \
  tests/RunOrNope.IntegrationTests/App .remember
git commit -m "feat: add RunOrNope desktop experience"
```
