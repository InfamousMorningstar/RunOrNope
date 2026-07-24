# RunOrNope Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a self-contained Windows desktop application that statically dissects PE and MSI inputs, explains evidence-backed capabilities, and never executes or uploads submitted samples.

**Architecture:** A .NET 10 WPF UI communicates through immutable contracts with an unelevated broker. The broker opens the sample once, establishes a capability-free AppContainer worker with Job Object limits, and validates hostile worker output before rendering it. Parsing, recursive artifact discovery, capability rules, YARA-X, reporting, and optional hash-only reputation are isolated behind narrow interfaces and tested independently.

**Tech Stack:** .NET SDK 10.0.302, C# 14, WPF, xUnit, FluentAssertions, FsCheck, Microsoft Windows AppContainer/Job Object/WinTrust/MSI APIs, AsmResolver, YARA-X C API, System.Text.Json, GitHub Actions.

## Global Constraints

- Windows 10/11 x64 support is limited to the exact serviced build matrix documented by the project.
- Local scans must never execute, load, install, repair, shell-open, preview, resolve, contact, or upload sample-controlled content.
- Hostile bytes and parser output never enter the WPF process without bounded DTO validation.
- Worker isolation is fail-closed; no AppContainer or policy failure may fall back to a normal process.
- Local analysis has no network access. VirusTotal is an explicit SHA-256-only action and never uploads files.
- Risk disposition and analysis completeness are independent.
- Parser failure, unsupported content, encryption, or policy truncation never becomes a favorable result.
- The private Slyden sample remains outside Git, packages, CI, logs, and public fixtures.
- Every implementation task ends with tests, review, and a Git commit.

---

## File Structure

```text
RunOrNope/
├── RunOrNope.slnx
├── global.json
├── Directory.Build.props
├── Directory.Packages.props
├── README.md
├── SECURITY.md
├── LICENSE
├── .gitignore
├── .editorconfig
├── src/
│   ├── RunOrNope.App/                 # WPF presentation only
│   ├── RunOrNope.Contracts/           # immutable, bounded IPC/report DTOs
│   ├── RunOrNope.Core/                # evidence, capabilities, verdicts
│   ├── RunOrNope.Intake/              # single-handle intake and identity
│   ├── RunOrNope.Broker.Windows/      # AppContainer and Job Object broker
│   ├── RunOrNope.Worker/              # restricted parser host
│   ├── RunOrNope.Analyzers.Pe/        # PE/CLR structural analysis
│   ├── RunOrNope.Analyzers.Msi/       # read-only MSI analysis
│   ├── RunOrNope.Analyzers.Content/   # strings, artifacts, ASAR/JAR/CAB
│   ├── RunOrNope.Rules/               # capability/YARA rule orchestration
│   └── RunOrNope.Reporting/           # script-free HTML and JSON
├── tests/
│   ├── RunOrNope.UnitTests/
│   ├── RunOrNope.IntegrationTests/
│   ├── RunOrNope.SecurityTests/
│   └── Fixtures/
├── rules/
├── schemas/
├── docs/
└── .github/workflows/
```

---

### Task 1: Reproducible Toolchain, Solution Skeleton, and Living README

**Files:**
- Create: `global.json`
- Create: `Directory.Build.props`
- Create: `Directory.Packages.props`
- Create: `RunOrNope.slnx`
- Create: `.editorconfig`
- Create: `.gitignore`
- Create: `README.md`
- Create: `src/*/*.csproj`
- Create: `tests/*/*.csproj`
- Create: `tests/RunOrNope.UnitTests/Architecture/ProjectGraphTests.cs`

**Interfaces:**
- Produces: a buildable .NET 10 solution with centralized dependency versions and a documented project graph.
- Consumes: no earlier task.

- [ ] **Step 1: Install the repository-local .NET 10.0.302 SDK**

Use Microsoft’s official install script to place the SDK under an ignored `.tools/dotnet` directory. Verify:

```powershell
New-Item -ItemType Directory -Path .tools -Force | Out-Null
Invoke-WebRequest `
  -Uri "https://dot.net/v1/dotnet-install.ps1" `
  -OutFile ".tools\dotnet-install.ps1"
& .\.tools\dotnet-install.ps1 `
  -Version "10.0.302" `
  -InstallDir ".tools\dotnet" `
  -NoPath
& .\.tools\dotnet\dotnet.exe --version
```

Expected: `10.0.302`.

- [ ] **Step 2: Write the failing project-graph test**

```csharp
[Fact]
public void Wpf_project_must_not_reference_parser_projects()
{
    ProjectGraph.Load("RunOrNope.slnx")
        .ReferencesFrom("RunOrNope.App")
        .Should().NotContain(name => name.Contains("Analyzers", StringComparison.Ordinal));
}
```

- [ ] **Step 3: Scaffold projects and central build settings**

Set `TargetFramework` to `net10.0-windows10.0.19041.0`, enable nullable reference types, warnings-as-errors, deterministic builds, analyzers, locked restore, and x64 release publishing.

- [ ] **Step 4: Create the initial README**

Document purpose, current status, “never executed / never uploaded,” supported root formats, build prerequisites, architecture diagram, limitations, privacy, and roadmap. Mark unimplemented features as roadmap rather than working functionality.

- [ ] **Step 5: Restore, build, and run tests**

```powershell
& .\.tools\dotnet\dotnet.exe restore --use-lock-file
& .\.tools\dotnet\dotnet.exe restore --locked-mode
& .\.tools\dotnet\dotnet.exe build -c Release --no-restore
& .\.tools\dotnet\dotnet.exe test -c Release --no-build
```

Expected: build succeeds and project-graph test passes.

- [ ] **Step 6: Commit**

```powershell
git add .
git commit -m "build: scaffold RunOrNope solution"
```

---

### Task 2: Immutable Evidence, Completeness, Capability, and Verdict Contracts

**Files:**
- Create: `src/RunOrNope.Contracts/ScanContracts.cs`
- Create: `src/RunOrNope.Core/Evidence/EvidenceModels.cs`
- Create: `src/RunOrNope.Core/Verdicts/VerdictEngine.cs`
- Create: `src/RunOrNope.Core/Verdicts/ScoringPolicy.cs`
- Create: `tests/RunOrNope.UnitTests/Core/VerdictEngineTests.cs`
- Create: `schemas/runornope-report-v1.schema.json`

**Interfaces:**
- Produces: `ScanRequest`, `ScanResult`, `ArtifactNode`, `Observation`, `CapabilityFinding`, `AnalysisStatus`, `RiskDisposition`, `VerdictEngine.Evaluate`.
- Consumes: solution conventions from Task 1.

- [ ] **Step 1: Write failing verdict tests**

```csharp
[Fact]
public void Incomplete_analysis_never_becomes_favorable()
{
    var result = VerdictEngine.Evaluate(TestScan.IncompleteWithoutFindings());
    result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
    result.RiskDisposition.Should().BeNull();
}

[Fact]
public void Correlated_entropy_findings_cannot_create_high_risk()
{
    var result = VerdictEngine.Evaluate(TestScan.WithEntropyHeuristics(20));
    result.RiskDisposition.Should().NotBe(RiskDisposition.HighRisk);
}
```

- [ ] **Step 2: Implement immutable records and bounded enums**

Use closed enums for evidence status, parser confidence, evidence confidence, severity, analysis status, risk family, and artifact completeness. Make all collections immutable at trust boundaries.

- [ ] **Step 3: Implement deterministic family-capped scoring**

Score independent families, cap correlated contributions, require strong application-linked implementation evidence for high risk, and keep positive trust evidence non-subtractive.

- [ ] **Step 4: Validate JSON schema and deterministic serialization**

Add golden serialization tests and reject unknown oversized collections, excessive strings, bidi controls, and invalid enum values at IPC/report boundaries.

- [ ] **Step 5: Test and commit**

```powershell
& .\.tools\dotnet\dotnet.exe test tests\RunOrNope.UnitTests -c Release
git add src tests schemas
git commit -m "feat: add evidence and verdict model"
```

---

### Task 3: Single-Handle Safe File Intake

**Files:**
- Create: `src/RunOrNope.Intake/SafeFileIntake.cs`
- Create: `src/RunOrNope.Intake/FileIdentity.cs`
- Create: `src/RunOrNope.Intake/FormatSniffer.cs`
- Create: `tests/RunOrNope.UnitTests/Intake/SafeFileIntakeTests.cs`
- Create: `tests/RunOrNope.IntegrationTests/Intake/TamperRaceTests.cs`

**Interfaces:**
- Produces: `SafeFileIntake.OpenAsync(string, IntakePolicy, CancellationToken)` returning an owned read-only handle plus hashes, identity, size, and detected root format.
- Consumes: `ScanRequest` and format enums from Task 2.

- [ ] **Step 1: Write failing format and race tests**

Test extension mismatch, shared-write denial, file replacement, growth during hashing, named-pipe/device paths, reparse points, oversized files, and cancellation.

- [ ] **Step 2: Implement open-once intake**

Open with write/delete sharing denied, reject non-disk/device/reparse inputs, hash and parse through the same handle, compare stable Windows file identity and metadata, and never reopen by path.

- [ ] **Step 3: Implement bounded magic detection**

Recognize PE and MSI/CFBF roots by bytes. Return unsupported/invalid rather than dispatching from the extension.

- [ ] **Step 4: Test and commit**

```powershell
& .\.tools\dotnet\dotnet.exe test --filter "Intake" -c Release
git add src/RunOrNope.Intake tests
git commit -m "feat: add tamper-resistant file intake"
```

---

### Task 4: Fail-Closed AppContainer Worker Broker

**Files:**
- Create: `src/RunOrNope.Broker.Windows/NativeMethods.cs`
- Create: `src/RunOrNope.Broker.Windows/AppContainerProfile.cs`
- Create: `src/RunOrNope.Broker.Windows/JobObject.cs`
- Create: `src/RunOrNope.Broker.Windows/WorkerBroker.cs`
- Create: `src/RunOrNope.Worker/Program.cs`
- Create: `src/RunOrNope.Worker/WorkerProtocol.cs`
- Create: `tests/RunOrNope.SecurityTests/Isolation/AppContainerTests.cs`
- Create: `tests/RunOrNope.SecurityTests/Isolation/WorkerEscapeTests.cs`

**Interfaces:**
- Produces: `IWorkerBroker.AnalyzeAsync(SafeFileHandle, ScanRequest, CancellationToken)`.
- Consumes: Task 2 contracts and Task 3 safe handle.

- [ ] **Step 1: Write failing isolation tests**

Test absence of network capabilities, `ActiveProcessLimit = 1`, child-process denial, broker-only IPC handles, private-directory ACL, timeout, memory quota, kill-on-close, and explicit failure when AppContainer creation is blocked.

- [ ] **Step 2: Implement AppContainer profile and ACL lifecycle**

Create a unique capability-free profile/SID per worker, ACL only the input handle/IPC/private directory, and delete the profile after cleanup.

- [ ] **Step 3: Implement Job Object and process mitigations**

Apply resource limits before worker execution, disable extension points, dynamic code where compatible, child processes, and non-system image loads. Treat inability to verify any required setting as fatal.

- [ ] **Step 4: Implement length-prefixed bounded IPC**

Use a versioned request/response envelope over explicit anonymous pipes. Enforce maximum frame, string, collection, and total-result sizes before deserialization.

- [ ] **Step 5: Run security tests under IPv4/IPv6/loopback/proxy conditions**

Expected: worker cannot connect, create children, escape output ACLs, inherit unexpected handles, or survive broker disposal.

- [ ] **Step 6: Commit**

```powershell
git add src/RunOrNope.Broker.Windows src/RunOrNope.Worker tests/RunOrNope.SecurityTests
git commit -m "feat: isolate analysis workers with AppContainer"
```

---

### Task 5: PE, Authenticode, and CLR Structural Analysis

**Files:**
- Create: `src/RunOrNope.Analyzers.Pe/MinimalPeReader.cs`
- Create: `src/RunOrNope.Analyzers.Pe/PeAnalyzer.cs`
- Create: `src/RunOrNope.Analyzers.Pe/AuthenticodeVerifier.cs`
- Create: `src/RunOrNope.Analyzers.Pe/ClrMetadataAnalyzer.cs`
- Create: `src/RunOrNope.Analyzers.Pe/PeObservations.cs`
- Create: `tests/RunOrNope.UnitTests/Pe/*.cs`
- Create: `tests/Fixtures/Pe/README.md`

**Interfaces:**
- Produces: `IArtifactAnalyzer.AnalyzeAsync(ArtifactInput, AnalysisContext, CancellationToken)` for PE/CLR.
- Consumes: evidence contracts and bounded artifact streams.

- [ ] **Step 1: Generate benign synthetic PE fixtures**

Build fixtures for imports, resources, RWX sections, malformed RVAs, overlays, CLR metadata, P/Invoke, and signature-state mocks. Do not use private malware in unit tests.

- [ ] **Step 2: Implement minimal PE validation**

Use checked arithmetic for DOS/COFF/optional headers, sections, directories, RVA mapping, certificate offsets, and overlay boundaries.

- [ ] **Step 3: Integrate the pinned AsmResolver package**

Extract richer imports, delay imports, resources, TLS, debug, load config, mitigations, CLR metadata, and entry-point evidence. Parser disagreement becomes an observation and may reduce completeness.

- [ ] **Step 4: Implement offline/cache-only WinTrust verification**

Record all signatures, exact errors, timestamp, catalog context, trust mode, and indeterminate revocation. Add strict-padding and malformed-signature tests.

- [ ] **Step 5: Add bounded CLR metadata and IL linkage**

Decode metadata and relevant IL without assembly loading. Build a bounded direct-call graph and distinguish application implementation from library/API presence.

- [ ] **Step 6: Test and commit**

```powershell
& .\.tools\dotnet\dotnet.exe test --filter "Pe|Authenticode|Clr" -c Release
git add src/RunOrNope.Analyzers.Pe tests
git commit -m "feat: add PE and CLR static analysis"
```

---

### Task 6: Artifact Graph, Strings, and Safe Nested Content

**Files:**
- Create: `src/RunOrNope.Analyzers.Content/ArtifactGraphBuilder.cs`
- Create: `src/RunOrNope.Analyzers.Content/ExtractionBudget.cs`
- Create: `src/RunOrNope.Analyzers.Content/StringExtractor.cs`
- Create: `src/RunOrNope.Analyzers.Content/AsarReader.cs`
- Create: `src/RunOrNope.Analyzers.Content/JarClassReader.cs`
- Create: `src/RunOrNope.Analyzers.Content/ArchivePathPolicy.cs`
- Create: `tests/RunOrNope.UnitTests/Content/*.cs`
- Create: `tests/RunOrNope.SecurityTests/Extraction/*.cs`

**Interfaces:**
- Produces: a SHA-256-deduplicated artifact DAG and bounded observations for ASAR/JAR/class/text content.
- Consumes: `ArtifactNode`, `Observation`, and scan policy.

- [ ] **Step 1: Write decompression, traversal, recursion, and accounting tests**

Cover `..`, UNC/device/ADS names, case collisions, reparse points, duplicate hashes, huge declared sizes, compression bombs, depth, total-byte limits, and disk reserve.

- [ ] **Step 2: Implement streamed budget accounting**

Count logical entries and compressed/expanded bytes even when hashes deduplicate analysis. Use immutable hard ceilings and explicit `TruncatedByPolicy`.

- [ ] **Step 3: Implement strings with provenance**

Extract ASCII/UTF encodings with offsets, region ownership, bidi/control escaping, context-aware URL/path classification, and bounded transforms with derivation chains.

- [ ] **Step 4: Implement bounded ASAR and JAR/class readers**

Parse documented structures without Node/Java. Separate application packages from dependencies and mark unresolved dynamic linkage.

- [ ] **Step 5: Test and commit**

```powershell
& .\.tools\dotnet\dotnet.exe test --filter "Content|Extraction|Asar|Jar" -c Release
git add src/RunOrNope.Analyzers.Content tests
git commit -m "feat: add bounded recursive artifact analysis"
```

---

### Task 7: Read-Only MSI and Passive Installer Adapters

**Files:**
- Create: `src/RunOrNope.Analyzers.Msi/MsiDatabase.cs`
- Create: `src/RunOrNope.Analyzers.Msi/MsiAnalyzer.cs`
- Create: `src/RunOrNope.Analyzers.Msi/CustomActionDecoder.cs`
- Create: `src/RunOrNope.Analyzers.Msi/MsiTables.cs`
- Create: `src/RunOrNope.Worker/Adapters/AdapterManifest.cs`
- Create: `tests/RunOrNope.UnitTests/Msi/*.cs`
- Create: `tests/RunOrNope.SecurityTests/Msi/NoInstallTests.cs`

**Interfaces:**
- Produces: MSI observations, embedded artifact streams, missing-media completeness events, and verified passive adapter results.
- Consumes: isolated worker and artifact graph interfaces.

- [ ] **Step 1: Build harmless MSI fixtures**

Create fixtures containing every supported custom-action type, embedded/external CAB references, services, Registry entries, conditions, and missing media.

- [ ] **Step 2: Implement the minimal read-only MSI API surface**

P/Invoke only database/query/record/stream/close functions. Prohibit package-session, install, repair, transform-apply, patch, advertise, UI, and custom-action APIs by architecture test.

- [ ] **Step 3: Decode and correlate MSI behavior**

Join `CustomAction`, sequence, `Binary`, `File`, `Property`, service, Registry, environment, shortcut, and media tables. Preserve conditional uncertainty.

- [ ] **Step 4: Add verified passive adapter manifest**

Pin approved 7-Zip/innoextract versions, licenses, and SHA-256 values. Launch each only as its own AppContainer worker; unsupported versions yield incomplete results.

- [ ] **Step 5: Test and commit**

```powershell
& .\.tools\dotnet\dotnet.exe test --filter "Msi|InstallerAdapter" -c Release
git add src/RunOrNope.Analyzers.Msi src/RunOrNope.Worker tests
git commit -m "feat: add read-only installer analysis"
```

---

### Task 8: Capability Rules and YARA-X Evidence Provider

**Files:**
- Create: `src/RunOrNope.Rules/CapabilityRuleEngine.cs`
- Create: `src/RunOrNope.Rules/RuleModels.cs`
- Create: `src/RunOrNope.Rules/YaraXScanner.cs`
- Create: `rules/capabilities/*.yaml`
- Create: `rules/yara/*.yar`
- Create: `rules/manifest.json`
- Create: `docs/RULE_AUTHORING.md`
- Create: `tests/RunOrNope.UnitTests/Rules/*.cs`

**Interfaces:**
- Produces: versioned `CapabilityFinding` and `RuleDetection` results with exact evidence provenance.
- Consumes: observations and artifact graph.

- [ ] **Step 1: Write negative and reinforcing-cluster tests**

Ensure lone strings/imports and library-only APIs remain weak. Require linked clusters for Discord targeting, credential access, persistence, process injection, surveillance, evasion, destructive behavior, and exfiltration staging.

- [ ] **Step 2: Implement declarative capability rules**

Rules declare required/optional evidence, application-linkage requirements, benign explanations, severity, confidence ceiling, family, and documentation.

- [ ] **Step 3: Integrate pinned YARA-X in the worker**

Compile trusted rules before activation, scan bounded artifact bytes, capture identifiers/offsets/tags/provenance, and treat timeouts as incomplete.

- [ ] **Step 4: Document rule semantics and review requirements**

Explain that matches are detections, not proof of execution or incident outcome.

- [ ] **Step 5: Test and commit**

```powershell
& .\.tools\dotnet\dotnet.exe test --filter "Rules|Yara" -c Release
git add src/RunOrNope.Rules rules docs tests
git commit -m "feat: add explainable capability rules"
```

---

### Task 9: Script-Free Reports and Privacy Controls

**Files:**
- Create: `src/RunOrNope.Reporting/JsonReportWriter.cs`
- Create: `src/RunOrNope.Reporting/HtmlReportWriter.cs`
- Create: `src/RunOrNope.Reporting/RedactionPolicy.cs`
- Create: `src/RunOrNope.Reporting/SafeText.cs`
- Create: `tests/RunOrNope.UnitTests/Reporting/*.cs`
- Create: `docs/REPORT_SCHEMA.md`

**Interfaces:**
- Produces: bounded, deterministic JSON and self-contained script-free HTML.
- Consumes: validated `ScanResult`.

- [ ] **Step 1: Write report-injection and redaction tests**

Test HTML/attribute injection, `file:`/`javascript:` strings, bidi controls, huge values, secret-like strings, hostile filenames, invalid UTF, and duplicate evidence.

- [ ] **Step 2: Implement typed encoding and default redaction**

Render sample URLs as inert text, add restrictive CSP, use safe generated export names, and expose explicit full-evidence mode with privacy warning.

- [ ] **Step 3: Validate JSON schema and golden reports**

Reports include hashes, versions, limits, completeness, evidence, countervailing facts, and reproducibility metadata without embedding sample bytes.

- [ ] **Step 4: Test and commit**

```powershell
& .\.tools\dotnet\dotnet.exe test --filter "Reporting" -c Release
git add src/RunOrNope.Reporting tests docs schemas
git commit -m "feat: add safe evidence reports"
```

---

### Task 10: WPF User Experience and Explicit Hash Reputation

**Files:**
- Create: `src/RunOrNope.App/App.xaml`
- Create: `src/RunOrNope.App/MainWindow.xaml`
- Create: `src/RunOrNope.App/ViewModels/MainViewModel.cs`
- Create: `src/RunOrNope.App/Views/CapabilityCard.xaml`
- Create: `src/RunOrNope.App/Services/VirusTotalHashLookup.cs`
- Create: `tests/RunOrNope.UnitTests/App/*.cs`
- Create: `tests/RunOrNope.IntegrationTests/App/ScanWorkflowTests.cs`

**Interfaces:**
- Produces: drag/drop and browse workflow, Quick/Deep scan, cancellation, capability cards, report export, explicit SHA-256 lookup.
- Consumes: broker and report interfaces.

- [ ] **Step 1: Write view-model workflow tests**

Cover invalid input, progress, cancellation, worker failure, incomplete analysis, high-risk plus incomplete, export, keyboard actions, and VirusTotal confirmation.

- [ ] **Step 2: Implement accessible WPF shell**

Keep code-behind minimal. Virtualize large finding collections. Display “Sample never executed,” “Sample never uploaded,” completeness, signer state, strongest evidence, and unresolved content.

- [ ] **Step 3: Implement capability cards**

Show plain-language ability, impact, evidence tier, application/library attribution, reachability, exact source, benign explanations, limitations, and recommendation.

- [ ] **Step 4: Implement explicit hash-only VirusTotal lookup**

Require confirmation, display the exact SHA-256 and destination, disable redirects, bound responses, and keep reputation separate from verdict scoring.

- [ ] **Step 5: Test and commit**

```powershell
& .\.tools\dotnet\dotnet.exe test --filter "App|ScanWorkflow" -c Release
git add src/RunOrNope.App tests
git commit -m "feat: add RunOrNope desktop experience"
```

---

### Task 11: Detailed README, Security Documentation, and GitHub Automation

**Files:**
- Modify: `README.md`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `docs/ARCHITECTURE.md`
- Create: `docs/THREAT_MODEL.md`
- Create: `docs/PRIVACY.md`
- Create: `docs/LOCAL_MALWARE_TESTING.md`
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`
- Create: `.github/dependabot.yml`

**Interfaces:**
- Produces: public documentation and pinned CI/release automation.
- Consumes: actual implemented behavior from Tasks 1–10.

- [ ] **Step 1: Rewrite README against the working application**

Include screenshots, one-minute start, what it analyzes, how it works, capability examples, result meanings, privacy, no-execution design, supported formats, limitations, installation, portable releases, building, testing, rules, reports, FAQ, roadmap, and attribution.

- [ ] **Step 2: Document security and architecture**

Publish trust boundaries, AppContainer design, third-party adapters, residual risks, report privacy, vulnerability reporting, and safe local private-sample setup.

- [ ] **Step 3: Add hardened GitHub Actions**

Pin actions by full commit SHA, use least permissions, locked restore, test/build/security/license/SBOM gates, and prevent untrusted PR workflows from accessing secrets or release signing.

- [ ] **Step 4: Validate every README command on a clean checkout**

Expected: documented restore, build, test, publish, and scan-demo commands work exactly as written.

- [ ] **Step 5: Commit**

```powershell
git add README.md SECURITY.md CONTRIBUTING.md docs .github
git commit -m "docs: explain RunOrNope and secure its delivery"
```

---

### Task 12: Private Slyden Regression, Release Verification, and Packaging

**Files:**
- Create: `tests/RunOrNope.SecurityTests/PrivateSamples/SlydenRegressionTests.cs`
- Create: `tests/private-samples.example.json`
- Modify: `.gitignore`
- Create: `scripts/verify-release.ps1`
- Create: `scripts/publish-portable.ps1`
- Create: `THIRD-PARTY-NOTICES.md`

**Interfaces:**
- Produces: verified portable x64 package and release evidence.
- Consumes: complete application and private local sample configuration.

- [ ] **Step 1: Add hash-gated private fixture harness**

The harness accepts a local path only when its SHA-256 matches the private configuration. It redacts paths, disables network, monitors process/image-load/filesystem/Registry behavior, and never copies the sample into the repository or output.

- [ ] **Step 2: Define Slyden assertions from prior evidence**

Assert nested installer/Electron/Java/PE discovery, Discord client/data targeting evidence, analysis completeness disclosures, and no execution. Assertions must be general capability outcomes, not filename/hash special cases in production code.

- [ ] **Step 3: Run the full verification matrix**

```powershell
& .\.tools\dotnet\dotnet.exe test -c Release
& .\scripts\verify-release.ps1
```

Expected: all tests pass; no process launch, image load, network, sample copy, report injection, parser crash, or untriaged dependency issue.

- [ ] **Step 4: Publish self-contained portable package**

```powershell
& .\scripts\publish-portable.ps1 -Runtime win-x64
```

Expected: deterministic package containing WPF app, broker, workers, verified adapters/rules, notices, README, and checksums; no samples or private paths.

- [ ] **Step 5: Independent security and product review**

Request agent reviews of the implementation against the design, the no-execution boundary, result accuracy, README truthfulness, and release contents. Fix every critical/important issue.

- [ ] **Step 6: Commit**

```powershell
git add tests scripts .gitignore THIRD-PARTY-NOTICES.md
git commit -m "test: verify RunOrNope release safety"
```

- [ ] **Step 7: Push**

```powershell
git push -u origin master
```

Expected: GitHub contains source, documentation, commits, and workflows; it does not contain malware or private evidence.
