# WPF Experience and Hash Reputation Slice — Design

**Date:** July 29, 2026
**Status:** Approved with shared precursor landed
**Parent design:** `docs/superpowers/specs/2026-07-24-run-or-nope-design.md`
**Plan task:** Task 10 — WPF User Experience and Explicit Hash Reputation
**Builds on:** `docs/superpowers/specs/2026-07-29-safe-reporting-slice-design.md`

## 1. Purpose

Deliver RunOrNope's first desktop workflow: select a local PE/MSI, acquire it
through the tamper-resistant intake boundary, analyze it in the capability-free
AppContainer worker, explain the validated result without collapsing evidence
tiers or completeness, export a safe report, and optionally perform an explicit
VirusTotal lookup using only the sample's SHA-256.

The application never executes, previews, shell-opens, resolves, repairs, installs,
or uploads a submitted sample. Local analysis remains network-free. VirusTotal is a
separate, user-confirmed reputation action and never changes the static verdict.

## 2. Scope

In scope:

- An accessible WPF shell with browse and drag/drop intake, Quick/Deep mode,
  progress, cancellation, keyboard actions, and clear failure states.
- Capability cards that preserve all evidence-tier and provenance fields.
- HTML and JSON report export through the Task 9 writers.
- A memory-only, session-scoped VirusTotal API key entered through `PasswordBox`.
- Explicit SHA-256-only VirusTotal file-report lookup with confirmation, redirect
  denial, bounded response parsing, and a separate reputation display.
- Unit tests for view-model state transitions and reputation protocol enforcement,
  plus integration tests for the scan coordinator.

Out of scope:

- Persisting API credentials, DPAPI, Windows Credential Manager, or account setup.
- Uploading or rescanning a file, URL/domain/IP lookup, opening a VirusTotal web
  page, or downloading anything referenced by a response.
- Changing `ScanResult`, verdict scoring, thresholds, rule tiers, analyzer output,
  worker capabilities, or worker network policy.
- Worker package signing and portable distribution, which land in Task 12.
- Automatic update checks, telemetry, report preview, or shell-opening exports.

## 3. Landed shared precursor: preserve the single-handle chain

Before commit `b0daf7a`, the public APIs could not be composed safely by the App:

- `SafeFileIntake.OpenAsync` returns a `SafeFileLease` that correctly owns the only
  validated, stable handle.
- `IWorkerBroker.AnalyzeAsync` accepted a raw `SafeFileHandle`.
- `SafeFileLease` intentionally exposes no public handle.

The App must not reopen the path after intake, and reflection or a public handle
property would weaken ownership. Commit `b0daf7a` landed this minimal shared change
on `feature/initial-build`:

```csharp
// RunOrNope.Intake — internal, not visible to the App
internal SafeFileHandle BorrowHandle() => GetHandle();

// RunOrNope.Intake/Properties/AssemblyInfo.cs
[assembly: InternalsVisibleTo("RunOrNope.Broker.Windows")]

// RunOrNope.Broker.Windows
public interface IWorkerBroker
{
    Task<ScanResult> AnalyzeAsync(
        SafeFileLease sample,
        ScanRequest request,
        CancellationToken cancellationToken);
}
```

Broker.Windows already referenced Intake, so the change added no project
dependency. Broker.Windows also already had
`InternalsVisibleTo("RunOrNope.SecurityTests")`; demoting the raw-handle overload to
internal therefore preserves the existing 45-test isolation seam without making it
an application boundary.

`WorkerBroker` borrows the handle only for the awaited call and does not dispose it.
It holds `SafeHandle.DangerousAddRef` across the borrow so cancellation-driven
caller disposal cannot close the OS handle underneath an in-flight worker. The App
owns and disposes the lease after analysis. The raw-handle entry point is now an
internal implementation method used by security tests. Tests prove a disposed lease
fails closed and the broker receives the exact intake-owned handle without reopening
the sample.

**Superseded:** exposing `SafeFileLease.Handle` publicly was rejected because any UI
consumer could close, retain, or misuse the ownership-bearing handle. Adding a
path-taking broker overload was rejected because reopening by path destroys the
single-handle tamper guarantee. Making App a friend of Intake was rejected because
hostile-file primitives do not belong in the presentation assembly.

This precursor is complete and must not be re-implemented in the delivery lane.

### 3.1 Known real-path blocker

An end-to-end scan through an intake-opened handle currently causes the worker to
write a truncated response frame; the broker correctly maps that protocol failure
to `IsolationUnavailable`. It also reproduces through the internal raw-handle path,
so it predates the lease-taking precursor. The skipped
`HandleChainTests.Analysis_DoesNotDisposeTheCallersLease` records the blocker.

Task 10 builds `ScanCoordinator` against `IWorkerBroker` and verifies orchestration
with a fake broker. It does not modify or duplicate broker/worker launch-path work.
The parsing lane owns the pre-existing fix. Until that separate fix lands, Task 10
must not claim that real packaged-worker end-to-end scanning succeeds.

## 4. Application architecture

The App remains presentation/orchestration only and references no analyzer. Its
testable service boundaries are:

```csharp
public interface IScanCoordinator
{
    Task<CompletedScan> ScanAsync(
        string path, ScanMode mode, CancellationToken cancellationToken);
}

public sealed record CompletedScan(
    ScanResult Result,
    VerdictResult Verdict,
    string Sha256,
    long Size);

public interface IReportExportService
{
    Task ExportAsync(
        ScanResult result,
        ReportFormat format,
        ReportEvidenceMode evidenceMode,
        string destinationPath,
        CancellationToken cancellationToken);
}

public interface IHashReputationLookup
{
    Task<HashReputationResult> LookupAsync(
        string sha256, string apiKey, CancellationToken cancellationToken);
}

public interface IUserInteraction
{
    string? ChooseSample();
    ReportDestination? ChooseReportDestination(string suggestedName);
    Task<bool> ConfirmHashLookupAsync(string sha256, Uri destination);
}
```

`ScanCoordinator` is the only App component that touches intake and broker APIs:

1. `SafeFileIntake.OpenAsync(path, IntakePolicy.Default, token)` validates locality,
   identity, size, format, and computes SHA-256 through the owned handle.
2. Unsupported roots remain explicit results; they are never routed by extension.
3. It awaits `IWorkerBroker.AnalyzeAsync(lease, new ScanRequest(string.Empty,
   mode), token)`. The request path is deliberately empty because the worker
   receives a handle and must not receive or resolve the original path.
4. It cross-checks that the validated result's root artifact hash/size match the
   lease (the broker also checks worker output at its trust boundary).
5. It evaluates `VerdictEngine` and returns `CompletedScan`.
6. It disposes the lease in all success, failure, and cancellation paths.

The App never binds raw worker/parser output. Only the validated `ScanResult`,
`VerdictResult`, and bounded view models reach WPF controls.

Task 10 keeps broker construction injectable. Task 12 supplies the authenticated
packaged-worker manifest, signature, trusted key, and production composition.
Until that packaging is present, production composition fails closed with
`IsolationUnavailable`; it never starts an ordinary process.

## 5. Main view-model state

`MainViewModel` owns one operation at a time and exposes immutable/display-ready
state:

```csharp
public enum ScanUiState
{
    Idle, Acquiring, Analyzing, Completed, Cancelling, Cancelled, Failed
}

public sealed class MainViewModel : INotifyPropertyChanged, IDisposable
{
    public ScanUiState State { get; }
    public ScanMode SelectedMode { get; set; }
    public string? SelectedPath { get; }
    public string StatusMessage { get; }
    public CompletedScan? CompletedScan { get; }
    public IReadOnlyList<CapabilityCardViewModel> CapabilityCards { get; }
    public HashReputationViewModel Reputation { get; }
    public bool CanStart { get; }
    public bool CanCancel { get; }
    public bool CanExport { get; }
    public bool CanLookupHash { get; }
}
```

Commands:

- `BrowseCommand` (`Ctrl+O`) selects one candidate path and starts no operation.
- `ScanCommand` (`Ctrl+Enter`) starts the selected mode.
- `CancelCommand` (`Escape`) cancels the current intake/broker operation.
- `ExportHtmlCommand` (`Ctrl+Shift+H`) and `ExportJsonCommand`
  (`Ctrl+Shift+J`) export the completed validated result.
- `LookupHashCommand` (`Ctrl+Shift+V`) begins the explicit confirmation flow.
- Drag/drop accepts exactly one file path and follows the same selection/scan path
  as Browse; multiple items, directories, remote/device paths, and non-file data
  are rejected before scan with neutral wording.

Starting a new scan clears the prior result, cards, errors, and reputation state.
It does not clear the session API key. Closing/disposal cancels work and clears the
key reference.

Expected intake, cancellation, isolation, and protocol failures become bounded
user-facing messages chosen by exception type. The UI never displays arbitrary
exception text because it can contain paths, server content, or credentials.
Unexpected exceptions are represented by a fixed generic failure message; this
slice adds no file or network logging.

The view model never converts an incomplete/unsupported/isolation result into a
favourable state. It displays `AnalysisStatus`, `ArtifactCompleteness`, and nullable
`RiskDisposition` separately. A high-risk candidate with incomplete analysis shows
both the risk disposition (when the engine retains it) and the incomplete banner.

## 6. WPF shell and accessibility

`App.xaml`, `MainWindow.xaml`, and a reusable `CapabilityCard` user control provide:

- a persistent safety banner: **Sample never executed** and
  **Sample never uploaded**;
- browse/drop selection, Quick/Deep radio controls, Scan and Cancel buttons;
- a live status region with `AutomationProperties.LiveSetting="Polite"`;
- separate summary rows for analysis status, completeness, risk disposition, root
  SHA-256, and size;
- an unresolved/incomplete-content panel that cannot be mistaken for a clean result;
- a virtualized `ItemsControl`/`ListBox` for large capability collections;
- report export controls and a distinct VirusTotal reputation panel;
- usable keyboard focus order, access keys, high-contrast-compatible system colors,
  minimum 44-device-independent-pixel primary targets, and text that does not rely
  on color alone.

The root window handles file-drop validation and `PasswordBox.PasswordChanged` only.
Standard WPF `PasswordBox` deliberately has no bindable `Password` dependency
property. Minimal code-behind passes the current value to
`MainViewModel.SetVirusTotalApiKey(string)` and clears it on window close; no
attached property mirrors the credential into the visual tree.

The API key input is a `PasswordBox`, not a `TextBox`, so the value is not exposed as
ordinary automation/accessibility text. Automation name/help text describes the
control without containing the value. Clipboard commands are not added.

No `SecureString` is used. Microsoft discourages it for new .NET development and it
does not provide meaningful protection here. A plain `string`, held only for the
session and never written anywhere, is the honest boundary. WPF necessarily creates
managed string instances when `PasswordBox.Password` is read; the application
minimizes lifetime and copies but does not claim memory secrecy it cannot provide.

## 7. Capability cards

Each `CapabilityCardViewModel` preserves and labels:

- title and potential impact;
- severity;
- evidence status and evidence confidence;
- parser confidence;
- application/dependency/installer/unknown linkage;
- reachability;
- risk family;
- recommended action;
- every cited observation id and resolved source artifact;
- source offset and region when present, otherwise `Not reported`;
- benign explanations and limitations.

Presence-only/Informational detections use neutral visual copy such as
`Context — API or library presence only`; structural High findings use
`Caution — strong structural evidence`. These labels are derived from the declared
fields, not title keywords. The UI never rewrites `ApiOrLibraryPresenceOnly` as
proof of behavior.

Cards expose exact evidence using bounded collections already validated by the
contract. No sample-controlled string becomes a URI, tooltip path, command
parameter that opens content, or raw XAML/markup.

## 8. Report export

Export is enabled only for a completed validated `ScanResult`, including results
whose analysis status is incomplete/unsupported/isolation-unavailable. The report
preserves those states; export availability is not a favourable verdict.

The user explicitly selects HTML or JSON, redacted (default) or full evidence, and a
destination through the Windows save dialog. The suggested HTML name comes from
`HtmlReportWriter.SuggestFileName`; JSON uses the same sanitization policy with
`.runornope.json`. `IReportExportService` obtains bytes from Task 9 and writes only
to the user-confirmed destination with asynchronous file I/O. It never previews or
shell-opens the output. Full evidence repeats the Task 9 privacy warning before the
save proceeds.

Export exceptions map to fixed messages and never include report contents, the
VirusTotal key, or arbitrary OS exception text.

## 9. Session API-key lifecycle

`MainViewModel` holds the VirusTotal key in a private nullable `string` field:

- set only from `PasswordBox.PasswordChanged`;
- retained across scans for the current window session;
- never put in a bindable property, command parameter, DTO, `ScanRequest`,
  `ScanResult`, report model, status text, exception, diagnostic message, or log;
- never persisted to configuration, registry, environment, disk, crash-recovery
  state, or `.remember`;
- never passed to Intake, Broker.Windows, Worker, Reporting, or verdict code;
- replaced when the user changes it, cleared when the PasswordBox is cleared, and
  dereferenced during view-model/window disposal.

The key cannot reach the worker. The worker is a capability-free AppContainer with
no network by design, and worker IPC contains only its versioned scan request. The
VirusTotal service lives in the App process and receives only SHA-256, key, and
cancellation token for the duration of one confirmed lookup.

`RedactionPolicy` is not a credential safeguard for this key. It protects reports
from secret-like strings discovered in sample-controlled evidence. The VirusTotal
credential is prevented from entering report/log/exception data paths at all.

## 10. Explicit VirusTotal confirmation

`LookupHashCommand` is enabled only when:

- a completed scan has a validated 64-character lowercase hexadecimal root SHA-256;
- the session key is non-empty;
- no scan or lookup is active.

Every request displays a confirmation dialog containing:

- the exact SHA-256 that will be disclosed;
- the fixed destination origin `https://www.virustotal.com`;
- the statement `Only this SHA-256 will be sent. The sample will not be uploaded.`;
- explicit Continue and Cancel actions, with Cancel as the default.

Declining confirmation performs no DNS/network operation and records `Skipped` in
the separate reputation panel. Confirmation is required again for every lookup,
including repeated lookup of the same hash.

The destination is fixed in code; sample-controlled text cannot influence host,
scheme, path prefix, headers, proxy, or request method.

## 11. VirusTotal HTTP protocol

`VirusTotalHashLookup` implements `IHashReputationLookup`. Production composition
uses a dedicated `HttpClient` with:

```csharp
new SocketsHttpHandler
{
    AllowAutoRedirect = false,
    AutomaticDecompression = DecompressionMethods.None,
    UseCookies = false,
}
```

The client has a fixed HTTPS base address
`https://www.virustotal.com/api/v3/`, a 15-second timeout, and no default API-key
header. For each confirmed request:

1. Validate SHA-256 as exactly 64 ASCII hexadecimal characters and normalize it to
   lowercase before constructing the request.
2. Reject an empty, CR-containing, or LF-containing API key locally.
3. Create `GET files/{sha256}` and put the key only in the `x-apikey` request
   header using a per-request `HttpRequestMessage`.
4. Send with `HttpCompletionOption.ResponseHeadersRead`.
5. Reject every 3xx response without following `Location`.
6. Accept at most 1 MiB of response bytes. Reject a declared larger
   `Content-Length`; otherwise stream through a counting buffer and abort at the
   same limit.
7. Parse one JSON document with a maximum depth of 32. Unknown fields are ignored;
   strings are not surfaced except the response's exact `data.id`, which must equal
   the requested SHA-256.

No query string is used, so the key does not enter proxy/server URL logs. The key
is never included in an exception message. The service creates fixed,
credential-free error categories:

```csharp
public enum HashReputationStatus
{
    Found, NotFound, Unauthorized, RateLimited, ServiceUnavailable,
    InvalidResponse, Skipped, Failed
}

public sealed record HashReputationResult(
    HashReputationStatus Status,
    string Sha256,
    int Malicious,
    int Suspicious,
    int Harmless,
    int Undetected,
    DateTimeOffset? LastAnalysisUtc);
```

The parser reads only
`data.attributes.last_analysis_stats.{malicious,suspicious,harmless,undetected}` and
`data.attributes.last_analysis_date`. All counts must be non-negative 32-bit
integers; dates must fit `DateTimeOffset.FromUnixTimeSeconds`. Missing/malformed
required fields produce `InvalidResponse`, not zero detections.

HTTP mapping:

- `200` → validated `Found`;
- `404` → `NotFound`;
- `401`/`403` → `Unauthorized`;
- `429` → `RateLimited`;
- `408`, `500`, `502`, `503`, `504` → `ServiceUnavailable`;
- other non-success → `Failed`;
- timeout/network/JSON/bounds errors → fixed categories without response bodies or
  exception messages.

The response body, headers, `Location`, and server error details are never logged or
shown. The API key is not retained by the service after the awaited call.

The VirusTotal v3 API documents `GET /api/v3/files/{id}` as a file-report lookup,
with a file object's id being its hash and authentication through the `x-apikey`
header. This slice supplies only the previously computed SHA-256 and never calls
upload, rescan, download, relationship, URL, or private-file endpoints.

## 12. Reputation is not verdict evidence

Reputation state is held in `HashReputationViewModel`, not in `ScanResult`,
`CapabilityFinding`, `VerdictResult`, report export, or scoring inputs. It appears
under a separately titled `Optional external reputation` panel with the lookup
time/status and counts.

No VirusTotal outcome changes:

- `AnalysisStatus` or `ArtifactCompleteness`;
- risk score or family caps;
- `RiskDisposition`;
- finding severity/evidence tier/reachability/linkage;
- recommended action or countervailing facts.

Found/clean-looking, NotFound, skipped, failed, unauthorized, rate-limited, and
unavailable results are all non-subtractive. A failed or skipped lookup never
improves a disposition. A lookup result is not exported in Task 10, preventing
external mutable state from being mistaken for reproducible static evidence.

## 13. Concurrency, cancellation, and lifecycle

Only one local scan and one lookup may be active, and a scan and lookup never run
concurrently. Commands derive `CanExecute` from state and are re-queried on every
transition.

Cancellation:

- cancels intake hashing and broker analysis through the same operation token;
- cancels HTTP send/body reading;
- leaves a neutral `Cancelled` state rather than `Failed`;
- never publishes a late result after a new operation begins;
- disposes the old `CancellationTokenSource`;
- does not convert cancellation into incomplete/favourable scan output.

An operation generation id guards against stale async completion overwriting newer
UI state. UI-bound state changes return to the WPF dispatcher through an injected
`IUiDispatcher`, while services use `ConfigureAwait(false)`.

Window close cancels work, clears the key reference, disposes the view model and
HTTP client, and waits for no unbounded background work. No sample handle or network
request survives application disposal.

## 14. Error and privacy language

User-visible messages are fixed and bounded:

- intake rejection: `RunOrNope could not safely acquire this local file.`
- isolation unavailable: `Analysis did not run because required isolation was unavailable.`
- incomplete: `Analysis is incomplete. No favourable conclusion is available.`
- hash not found: `VirusTotal has no report for this SHA-256. This is not evidence that the file is safe.`
- lookup unavailable: `External reputation could not be retrieved. The static verdict is unchanged.`
- invalid response: `VirusTotal returned an unusable response. The static verdict is unchanged.`

No message interpolates the API key, response body, exception message, original
path, or sample-controlled evidence. The selected display filename may be shown
only after extracting and bounding the leaf name; the full local path stays in the
selection control and is never sent externally or written into reports.

## 15. Testing

All tests use synthetic benign `ScanResult`s, fake service boundaries, and local
in-memory HTTP handlers. Tests never execute, preview, upload, contact VirusTotal,
or resolve sample-controlled network names.

### 15.1 Shared handle-chain tests

- `SafeFileLease` → broker uses the exact intake-owned handle without reopening the
  path.
- The App cannot access the borrowed handle API at compile time.
- A disposed lease fails before worker launch.
- Disposal racing an in-flight analysis leaves the borrowed OS handle valid until
  the broker releases its `DangerousAddRef`, after which lease disposal closes it.
- Success, intake failure, broker failure, and cancellation dispose the lease once.
- The scan request sent to the worker contains an empty path and selected mode.

### 15.2 Main view-model workflow

- Browse and single-file drop select a candidate; multiple items, directories,
  remote/device paths, and non-file data are rejected.
- Quick/Deep selection reaches `IScanCoordinator`.
- State transitions are deterministic:
  Idle → Acquiring/Analyzing → Completed; cancellation passes through Cancelling →
  Cancelled; expected failures end at Failed with fixed text.
- A second start is disabled while work is active; stale completion cannot replace
  a newer operation.
- Worker isolation failure displays `IsolationUnavailable` independently from
  disposition.
- Incomplete with no material findings shows a withheld disposition and explicit
  incomplete warning.
- High-risk plus incomplete shows both axes without downgrading either.
- Starting another scan clears prior cards/reputation but retains the session key.
- Disposal cancels operations and clears the key reference.
- Keyboard commands invoke the same behavior as buttons.

### 15.3 Capability cards and accessibility

- Presence-only/Informational debugger context is visibly distinguishable from a
  High/strong-structural process-injection finding.
- Every card exposes severity, evidence status/confidence, parser confidence,
  reachability, linkage, family, recommendation, observation id, source artifact,
  offset/region, benign explanations, and limitations.
- Missing offset/region displays `Not reported`.
- Large finding collections use a virtualizing items panel.
- Safety banners, accessible names, live status, tab order, and keyboard gestures
  are present; no color is the sole carrier of severity or completeness.
- Hostile validated strings are text-bound and cannot create XAML, commands, URIs,
  automation properties, or navigation.

### 15.4 Report export

- HTML/JSON export passes the completed `ScanResult`, selected evidence mode, and
  user-confirmed destination to the writer.
- Default export is redacted; full evidence requires the privacy warning.
- Hostile sample names produce safe suggested leaf names.
- Cancellation and I/O failure show fixed messages and never shell-open output.
- Export is unavailable without a completed validated result.

### 15.5 API-key containment

- The password control is `PasswordBox`, not `TextBox`, and no bindable/public view
  model property exposes its value.
- The key is retained across scans, replaceable, clearable, and dereferenced on
  disposal; no persistence API is called.
- The key never appears in `ScanRequest`, fake worker input, reports, reputation
  results, property-change notifications, status/error text, exception messages, or
  captured diagnostic output.
- A representative sample-controlled `api_key=...` string is handled by report
  redaction, while the user credential is proven absent from the report data path.
- No `SecureString` or credential-persistence type is used.

### 15.6 Confirmation and HTTP protocol

- Cancelled confirmation sends zero HTTP requests; every attempt requires a new
  confirmation.
- Confirmation displays the exact SHA-256, fixed destination, and hash-only
  disclosure language.
- A confirmed request is exactly
  `GET https://www.virustotal.com/api/v3/files/{lowercase-sha256}` with no query and
  only the key in `x-apikey`; request content is null.
- The handler has redirects disabled, cookies disabled, and decompression disabled.
- 301/302/307/308 are not followed, including redirects to a loopback or attacker
  host.
- Declared and streamed bodies over 1 MiB are rejected; JSON depth over 32,
  malformed JSON, negative/overflowed counts, invalid dates, missing stats, and
  mismatched `data.id` produce `InvalidResponse`.
- Valid 200 maps exact counts/date; 404, 401/403, 429, transient server statuses,
  other failures, timeout, cancellation, and network errors map to their fixed
  states without including bodies, headers, URLs, or exception text.
- CR/LF in the key is rejected before send; the key never enters a query string.

### 15.7 Verdict independence

- Found with zero malicious/suspicious counts does not lower score, disposition, or
  recommendation.
- Found with malicious counts does not raise static score or mutate findings.
- NotFound, Skipped, Unauthorized, RateLimited, ServiceUnavailable,
  InvalidResponse, and Failed leave verdict and completeness byte-for-byte
  unchanged.
- A failed/skipped lookup cannot enable report export or any favourable UI label.

### 15.8 Integration workflow

- A synthetic local PE acquired once flows through a fake broker to a validated
  result, verdict, cards, and report export; the path is never reopened by the App.
- Intake rejection, tamper detection, cancellation, and isolation failure release
  resources and show the correct independent axes.
- VirusTotal tests use an in-memory handler only and assert that no real network
  connection is attempted.

## 16. Files and dependencies

Delivery-lane files:

- `src/RunOrNope.App/App.xaml`, `App.xaml.cs`
- `src/RunOrNope.App/MainWindow.xaml`, `MainWindow.xaml.cs`
- `src/RunOrNope.App/ViewModels/MainViewModel.cs`
- `src/RunOrNope.App/ViewModels/CapabilityCardViewModel.cs`
- `src/RunOrNope.App/ViewModels/HashReputationViewModel.cs`
- `src/RunOrNope.App/Views/CapabilityCard.xaml`, `.xaml.cs`
- `src/RunOrNope.App/Services/ScanCoordinator.cs`
- `src/RunOrNope.App/Services/ReportExportService.cs`
- `src/RunOrNope.App/Services/VirusTotalHashLookup.cs`
- `src/RunOrNope.App/Services/AppServiceContracts.cs`
- `src/RunOrNope.App/Infrastructure/AsyncCommand.cs`
- `src/RunOrNope.App/Infrastructure/UiDispatcher.cs`
- `tests/RunOrNope.UnitTests/App/*.cs`
- `tests/RunOrNope.IntegrationTests/App/ScanWorkflowTests.cs`

Landed shared precursor (`b0daf7a`; do not edit in Task 10):

- `src/RunOrNope.Intake/SafeFileIntake.cs`
- `src/RunOrNope.Intake/Properties/AssemblyInfo.cs`
- `src/RunOrNope.Broker.Windows/WorkerBroker.cs`
- their existing unit/security tests

No new NuGet package is required. WPF, `HttpClient`, `System.Text.Json`, and existing
project references cover the slice. No analyzer, contract, reporting, scoring, or
verdict source changes are required.

## 17. Superseded approaches

- **Broker-owned VirusTotal:** rejected because the broker's purpose is local
  isolation and handle mediation. Adding reputation networking there blurs the
  capability-free worker story and adds no safety benefit.
- **HTTP in `MainViewModel`:** rejected because redirect, bounds, parsing, and
  credential rules need an independently testable audit boundary.
- **Persisted key with DPAPI:** deferred. Task 12 is portable; a credential artifact
  beside a copied application folder creates confusing portability and lifecycle
  semantics. Persistence is a later, explicit product decision.
- **`SecureString`:** rejected because modern .NET does not provide meaningful
  protection through it and Microsoft discourages its use. Memory-only `string`
  storage makes the actual guarantee precise.
- **Password in a `TextBox`:** rejected because ordinary text participates in the
  WPF automation/accessibility surface. `PasswordBox` is the required input.
- **Key redaction after the fact:** rejected. Task 9 redaction is for
  sample-controlled evidence, not user credentials. The API key must never enter
  report/log/exception models.
- **Automatic reputation lookup:** rejected because even a hash disclosure is a
  network/privacy action requiring explicit per-request confirmation.
- **Following VirusTotal redirects:** rejected because a redirect can disclose the
  credential/hash to a different destination and is unnecessary for the documented
  file-report endpoint.
- **Treating NotFound/zero detections as positive trust:** rejected because absence
  of external evidence is not favourable static evidence and reputation is a
  separate mutable axis.
