# RunOrNope Design Specification

**Date:** July 24, 2026  
**Status:** Approved conversational design, pending written-spec review  
**Target:** Windows 10/11 x64  
**Application:** Self-contained .NET 8 WPF desktop application

## 1. Purpose

RunOrNope is a defensive static-analysis application for people deciding whether an unfamiliar Windows executable or installer warrants being run. A user drags in a supported file, RunOrNope dissects it without executing it, and the application explains what capabilities the file appears to implement, what exact evidence supports each conclusion, how complete the analysis was, and what cautious action the user should take.

RunOrNope does not claim to prove a file is safe. Its job is to make static evidence understandable and reproducible.

## 2. Supported Inputs

Version 1 supports:

- Windows PE files: `.exe`, `.dll`, `.scr`, and `.sys`
- Windows Installer databases: `.msi`
- Nested artifacts discovered inside supported inputs, including PE files, CLR assemblies, NSIS payloads, Inno Setup payloads, CAB files, Electron ASAR archives, Java JAR/class files, ZIP-compatible containers, scripts, and high-value configuration files

Detection uses file structure and magic bytes rather than filename extensions. Archives supplied directly by the user are outside the version 1 scope. Archives found inside a supported PE or MSI are analyzed as nested artifacts.

Unsupported formats receive an explicit **Unsupported or invalid format** outcome. Unsupported versions of otherwise recognized packaging receive **Analysis incomplete**, not a favorable verdict.

## 3. Non-Negotiable Safety Boundary

RunOrNope treats every submitted byte as hostile.

It must never:

- Execute, install, repair, register, preview, or shell-open the submitted file
- Invoke installer initialization or custom actions
- Load a submitted assembly with reflection or `Assembly.Load`
- Load a submitted native library with `LoadLibrary`
- Invoke Node, Java, Electron, PowerShell, Command Prompt, scripts, or embedded executables from the sample
- Use Explorer shell extensions, icon handlers, property handlers, or preview handlers on the sample
- Resolve sample URLs, contact sample domains, or submit sample content
- Upload a submitted file to VirusTotal or any other service
- Interpret a parser failure as evidence that a capability is absent

Static parsing occurs in a disposable restricted worker, not in the WPF process.

Each worker receives:

- A read-only input handle
- A fresh private extraction directory
- No network capability
- No write access to the sample directory
- No inherited handles except required input/output/IPC handles
- A Windows Job Object with kill-on-close, CPU and memory limits, process-count limits, and output quotas
- Child-process creation blocked for managed parser jobs
- A strict wall-clock timeout and cancellation path

Approved passive native extractors may run only as the isolated worker or as the worker's sole explicitly permitted child. They never run under the full-trust WPF process.

Extracted artifacts use generated content-addressed names. Sample-controlled names remain metadata and are never used directly as filesystem paths.

## 4. High-Level Architecture

RunOrNope contains five bounded components:

### 4.1 WPF Desktop UI

The UI accepts a file, starts or cancels analysis, renders progress and findings, provides the optional hash-only VirusTotal lookup, and exports reports. It never parses sample bytes.

### 4.2 Analysis Broker

The broker creates an immutable request, opens the input read-only, launches a disposable restricted worker, enforces the Job Object and timeout policy, receives a bounded result DTO, validates it, and disposes of worker artifacts.

### 4.3 Restricted Analysis Worker

The worker performs format detection, hashing, bounded parsing, recursive artifact discovery, capability analysis, and rule evaluation. A crash, timeout, limit violation, or parser rejection becomes structured incompleteness evidence.

### 4.4 Evidence and Verdict Engine

The engine converts observations into transparent capability findings, tracks completeness and confidence independently from severity, caps correlated evidence families, and produces one cautious top-level outcome.

### 4.5 Report Engine

The report engine emits a portable interactive HTML report and a versioned JSON evidence report. Reports include input hashes, artifact relationships, parsers and rules used, limits reached, exact evidence, limitations, and verdict contributions.

## 5. Artifact Graph

Recursive discovery is a core abstraction. Analysis produces a content-addressed directed acyclic graph:

```text
outer installer
└── embedded archive
    └── Electron app.asar
        ├── JavaScript launcher
        ├── bundled Java/JAR application
        └── native PE library
```

Every artifact records:

- SHA-256 and size
- Parent artifact SHA-256
- Artifact kind and detected formats
- Original logical name, if present
- Extraction or carving method
- Source resource, stream, table, archive member, or byte range
- Exact offset and length when applicable
- Complete, carved, reconstructed, or truncated state
- Parser and parser version
- Analysis limits reached

Artifacts are deduplicated by SHA-256 before recursion.

Default policy limits:

- Maximum recursion depth: 5
- Maximum children per artifact: 10,000
- Maximum total artifacts: 25,000
- Maximum single materialized child: 2 GiB
- Maximum total extracted bytes: the lower of 10 GiB or 20 times the input size
- Maximum expansion ratio per member: 1,000 times
- Maximum aggregate expansion ratio: 200 times
- Adapter timeouts: 30 to 120 seconds, selected by format
- Adapter memory limits: 512 MiB to 2 GiB, selected by format

Limits are configurable in advanced settings. Hitting a limit records `TruncatedByPolicy` and forces an incomplete-analysis disclosure.

Extraction rejects absolute, drive, UNC, device, traversal, alternate-data-stream, reserved-device, case-collision, trailing-dot, and trailing-space paths. It does not follow symlinks, hard links, mount points, junctions, or other reparse points.

## 6. Analysis Pipeline

### 6.1 Identity and Trust

RunOrNope records:

- SHA-256, SHA-1, and MD5 for interoperability, with SHA-256 as the identity key
- Actual format and architecture
- File size and timestamps, clearly labeled as untrusted metadata
- Version-resource claims
- Manifest and requested execution level
- Authenticode certificate-table structure
- Windows trust verification result
- Embedded versus catalog signature
- Digest validity, chain state, signer, issuer, thumbprints, timestamp, revocation result, and trust-policy error
- Whether certificate validation used only local/cache data or performed an explicitly disclosed network operation

Signature presence is not signature validity. A valid signature is identity and integrity evidence, not proof of benign behavior. Unsigned software is not automatically suspicious.

### 6.2 PE Analysis

A minimal internal bounds-checked reader independently validates:

- DOS and PE signatures
- `e_lfanew`
- COFF and optional headers
- Section table
- Data-directory bounds
- RVA-to-file mappings
- Certificate-table location
- Section and overlay boundaries

A mature managed parser performs richer analysis:

- Imports, delay imports, exports, and forwarded exports
- Resources
- TLS callbacks
- CLR directory and metadata
- Debug and PDB information
- Load configuration and mitigation indicators
- Rich header
- Entry point
- Section characteristics, permissions, entropy, compressibility, and raw/virtual size relationships
- Checksums, overlays, and embedded content

Structural anomalies use checked arithmetic and bounded counts. Unknown future fields are retained as unknown, not labeled malicious.

PE heuristics include combinations such as:

- Entry point outside an executable section
- Writable and executable sections combined with execution primitives
- Invalid, overlapping, or out-of-file sections/directories
- Sparse imports combined with runtime API resolution
- TLS callbacks preceding the nominal entry point
- Suspicious resource or overlay payloads
- Import clusters associated with injection, persistence, credential access, surveillance, security-control interference, or destructive actions

Entropy, timestamps, uncommon section names, missing signatures, stripped debug data, and small import tables are weak context only. They cannot independently produce a high-risk verdict.

### 6.3 Managed .NET Analysis

RunOrNope detects CLR metadata structurally and never loads the assembly.

It inventories:

- Assembly identity, target framework, module references, and assembly references
- Strong-name state
- Types, methods, fields, properties, events, attributes, resources, and user strings
- P/Invoke mappings
- Entry points, initializers, exception regions, and method bodies
- ReadyToRun, Native AOT, mixed-mode, and single-file ambiguity

The worker decodes relevant IL instructions and constructs a bounded call graph. It resolves direct member references and tracks reachability tiers from identifiable roots. Lightweight constant propagation covers simple strings, concatenation, arrays, environment-folder resolution, paths, URL builders, resource extraction, `ProcessStartInfo`, and write-then-launch patterns.

Reflection, delegates, dynamic methods, expression trees, unmanaged transitions, encrypted strings, control-flow flattening, virtualized code, and downloaded code create explicit unresolved edges.

### 6.4 MSI Analysis

MSI packages are opened only through the Windows Installer database API using `MSIDBOPEN_READONLY`.

RunOrNope inventories:

- Summary information and code page
- `Property`, `Directory`, `Component`, `Feature`, and `FeatureComponents`
- `File`, `Media`, `MsiFileHash`, embedded and external cabinets
- `Binary`, `Icon`, `_Streams`, and `_Storages`
- `CustomAction`
- Install UI and execute sequence tables
- `Registry`, `RemoveRegistry`, `ServiceInstall`, and `ServiceControl`
- `Environment`, `Shortcut`, `IniFile`, and `RemoveFile`
- `AppSearch`, locator, signature, condition, transform, and external-source information

Custom-action type bits are decoded into action kind, source, target, timing, rollback/commit/deferred state, impersonation context, potential elevation, sequence, and condition. A custom action is legitimate MSI functionality and is not inherently malicious.

Embedded streams and cabinets become child artifacts and are recursively analyzed. Missing external cabinets, transforms, patches, or sources force an incomplete result. MSI installation, package sessions, UI preview, repair, patching, and custom-action invocation are prohibited.

### 6.5 Installer and Container Analysis

Installer recognition combines multiple structural signals and preserves every detected layer.

- NSIS and recognized archive payloads use a pinned current 7-Zip unpack-only backend in an isolated worker.
- Inno Setup uses a pinned `innoextract` backend when the format version is supported. Newer unsupported versions are reported as unparsed.
- Electron ASAR uses a custom bounded managed reader based on the documented format. It caps header size, JSON depth, entry count, offsets, lengths, and logical path lengths.
- CAB extraction uses a bounded maintained parser or the passive Windows Cabinet API.
- Java JARs use bounded ZIP parsing with traversal, entry, depth, size, and ratio protections.

The application never invokes installer switches, including switches advertised as extraction or help modes, because installer initialization may still execute code.

### 6.6 Electron and Java Analysis

Electron recognition combines runtime files, resources, ASAR layout, version data, and supporting installer evidence.

High-value Electron inspection includes:

- `package.json`
- Main and preload scripts
- HTML entry points
- Native `.node` modules
- Bundled executables
- `child_process` spawning and command construction
- Downloader and updater logic
- ASAR integrity fields and security fuses as posture evidence, not malware evidence

Java/JAR inspection parses without class loading:

- Manifest, main class, class path, multi-release entries, modules, service providers, and signature coverage
- Constant pools, class hierarchy, methods, descriptors, annotations, bootstrap methods, invokedynamic, method handles, strings, code references, and exception tables
- Native/JNA loading, process spawning, networking, filesystem traversal, archives, browser/Discord paths, DPAPI/NSS access, database access, webcam/screen APIs, and WebSockets

Application classes are separated from bundled dependencies using package clustering, Maven metadata, known hashes, manifests, call direction, and shaded-library signatures. Library capability alone cannot become confirmed application behavior.

### 6.7 Strings and Configuration

RunOrNope extracts bounded ASCII, UTF-8, UTF-16LE, and UTF-16BE strings with byte offsets and owning regions.

It identifies and ranks:

- URLs, domains, IP addresses, and WebSocket endpoints
- Paths and environment variables
- Registry keys
- Commands and script fragments
- Browser, Discord, wallet, credential-store, and security-tool identifiers
- Encoded or encrypted-looking blobs

Bounded transforms include high-confidence Base64, hexadecimal, simple constant folding, and context-supported XOR. Every transformed value retains its derivation chain. A URL string alone is not labeled command-and-control.

### 6.8 YARA-X

RunOrNope integrates a pinned YARA-X engine and curated, versioned rules.

Every match records:

- Engine and rule-pack version
- Rule namespace, identifier, tags, and metadata
- Matched artifact SHA-256
- Matched string identifiers and offsets
- Rule provenance and license
- Timeout or truncation state

YARA-X runs in the restricted worker with time and input limits. Rules are compiled and validated before release. A YARA match is labeled a rule detection, not proof of a malware family, capability execution, or incident outcome.

### 6.9 Optional VirusTotal Lookup

Local analysis performs no network access.

The separate **Look up this SHA-256 on VirusTotal** action:

- Requires explicit user activation and confirmation
- Displays the exact hash and endpoint before sending
- Sends only the SHA-256
- Never uploads file bytes
- Stores an API key only through an appropriate local secret mechanism
- Keeps reputation results separate from local static evidence
- Records lookup time and response provenance

## 7. Evidence Model

Every finding separates:

1. **Observation:** exact parsed fact, byte sequence, import, method, table row, string, resource, or structural property
2. **Interpretation:** behavior with which the observation is consistent
3. **Evidence status:**
   - Confirmed static implementation
   - Strong structural evidence
   - Linked implementation
   - API or library presence only
   - Heuristic
   - Unresolved
4. **Parse confidence:** completeness and reliability of parsing
5. **Evidence confidence:** strength of the interpretation
6. **Potential severity:** impact if reachable and used
7. **Application linkage:** application code, dependency, installer stub, or unknown
8. **Benign explanations**
9. **Limitations and unresolved questions**
10. **Exact source location and artifact**

Static reports use verbs such as `contains`, `imports`, `implements`, `references`, or `is consistent with`. They do not claim that a file `stole`, `uploaded`, `connected`, `injected`, or `persisted` without runtime or incident evidence.

## 8. Capability Model

The primary result answers what the scanned application appears able to do.

Capability families include:

- Network communication
- Downloading or uploading
- Browser-profile, cookie, login-database, and credential-store access
- Discord file and session-data targeting
- Wallet targeting
- Process and script launching
- Persistence through services, tasks, startup entries, WMI, Registry, or shortcuts
- Privilege and elevation behavior
- Process inspection, token manipulation, injection, and hollowing
- Screen, webcam, clipboard, and keyboard collection
- Broad filesystem and environment discovery
- Archive creation and data staging
- Security-tool modification or evasion
- Log, backup, recovery, and file deletion
- Embedded or downloaded executable payloads
- Packing, encryption, obfuscation, and anti-analysis

Every capability card provides:

- Plain-language capability title
- Potential impact
- Confidence and evidence tier
- Analysis completeness
- Application-versus-library attribution
- Reachability state
- Exact evidence and location
- Benign explanations
- Limitations
- Recommended action

Technical users can expand cards to view imports, methods, strings, MSI rows, rule matches, byte offsets, call relationships, and artifact hashes.

## 9. Verdict Model

Top-level outcomes are:

- **High-risk static indicators**
- **Caution warranted**
- **Few material static concerns identified**
- **Analysis incomplete**
- **Unsupported or invalid format**

The verdict engine tracks three dimensions independently:

- Parse confidence
- Evidence confidence
- Potential risk severity

Evidence is grouped into independent families. Each family has a capped contribution so correlated findings cannot dominate the outcome. Strong behavioral evidence or multiple reinforcing independent families are required for a high-risk result.

Weak context such as unsigned status, entropy, timestamp anomalies, uncommon section names, low prevalence, or packing cannot independently produce a high-risk verdict.

Positive evidence such as a trusted signature may reduce identity uncertainty but cannot erase behavioral findings.

Every report exposes verdict contributions, countervailing facts, rule/scoring versions, and completeness state. There are no safety guarantees or malware probability percentages.

Required favorable-result wording:

> No material concerns were identified by the enabled static checks. This does not rule out malicious behavior, downloaded components, environment-dependent actions, or vulnerabilities outside RunOrNope's rules. Do not run a file solely because this result is favorable.

Required incomplete-result wording:

> RunOrNope could not inspect all relevant content. This is not a clean result. Missing, unsupported, encrypted, malformed, or policy-limited content may conceal important behavior.

## 10. User Experience

The main workflow is:

1. Drag and drop a file or select **Browse**
2. Display SHA-256 and detected format immediately
3. Select **Quick Scan** or **Deep Scan**
4. Display bounded progress with the current artifact and parser
5. Review verdict, completeness, signer state, and capability cards
6. Expand technical evidence where desired
7. Export HTML or JSON
8. Optionally perform the separately confirmed VirusTotal hash lookup

Quick Scan covers:

- Outer-file identity and signature
- Core PE or MSI structure
- Imports, resources, strings, and structural anomalies
- YARA-X
- Obvious embedded payload discovery

Deep Scan adds:

- Recursive supported-container extraction
- Nested PE, CLR, Java, Electron, and installer analysis
- Bounded call relationships and constant propagation
- Longer adapter budgets within the same safety boundary

The interface prominently displays:

- **Sample never executed**
- **Sample never uploaded**
- Whether any optional network action occurred
- SHA-256
- Analysis completeness
- Signer status
- Strongest evidence
- Unsupported or unresolved content
- Parser, rules, and scoring versions

## 11. Reports

HTML reports are portable, self-contained, escaped against sample-controlled markup, and interactive without external resources. They mirror the UI's summary and expandable evidence.

JSON reports use a versioned schema and include:

- Scan metadata and policy
- Root file identity
- Artifact DAG
- Parser and rule versions
- Observations and findings
- Capability conclusions
- Completeness and limit events
- Verdict contributions
- Optional VirusTotal hash-lookup metadata

Reports never embed the submitted executable or extracted executable bytes.

## 12. Testing Strategy

Development is test-first.

### 12.1 Unit and Integration Coverage

Tests cover:

- PE32, PE32+, native, managed, mixed-mode, ReadyToRun, Native AOT, single-file, DLL, driver, and malformed PE structures
- Signed, unsigned, dual-signed, timestamped, expired, revoked, malformed, and catalog-signed trust states
- Every implemented MSI table and custom-action family
- Internal and external cabinets, missing sources, transforms, and unsupported patch semantics
- NSIS, Inno Setup, Electron ASAR, JAR, class, CAB, resources, and overlays
- String encodings, transforms, entropy, imports, call linkage, evidence, scoring, and reports
- Quick and Deep scan orchestration
- Cancellation, crash recovery, and resource limits

### 12.2 Adversarial Parser Tests

The corpus contains:

- Truncation at structural boundaries
- Invalid and overlapping offsets, lengths, RVAs, sections, tables, and streams
- Integer-overflow values and absurd counts
- Invalid text encodings and nesting
- Deep recursive graphs and duplicate artifacts
- Decompression bombs and extreme ratios
- Traversal, absolute, device, alternate-data-stream, collision, and reparse-point paths
- Huge resources, overlays, ASAR headers, MSI rows, and string sets

Property-based and coverage-guided fuzz tests target PE, CLR metadata, OLE/CFBF, MSI, CAB, ASAR, resource, certificate, and archive parsers.

### 12.3 Verdict and False-Positive Testing

Distinct benign and suspicious/malicious evaluation sets are stratified by:

- Format, architecture, and packaging
- Signed and unsigned state
- Managed and native code
- Packed and unpacked files
- Installer framework
- Software category, age, and vendor
- Malware family and campaign

Related versions, shared templates, vendors, signers, and malware families remain in the same split to prevent evaluation leakage.

Measurements include:

- False-positive and false-negative rates by stratum
- Precision and recall at verdict thresholds
- Incomplete-analysis rate
- Parser crash and timeout rates
- Evidence-confidence calibration
- Verdict stability across rule and parser updates

Every high-risk false positive requires review before release.

### 12.4 No-Execution and Privacy Tests

Tests prove:

- Samples and embedded artifacts are never executed or loaded
- No installer, repair, registration, custom action, preview, script, Java, Node, Electron, or shell path is invoked
- Managed worker child-process creation is blocked
- Local scans create no DNS requests, outbound connections, or uploads
- VirusTotal sends only the explicitly confirmed SHA-256
- Extracted bytes remain within the worker's private directory
- Worker limits, restricted identity, cancellation, and kill-on-close function correctly

### 12.5 Slyden Local Regression

`SlydenSetupV2.exe` is used only as a local, read-only Deep Scan regression sample.

The test:

- Requires the exact approved SHA-256 before reading
- Has no network
- Monitors process creation
- Expects nested installer, Electron, Java, and PE discovery
- Expects evidence for confirmed Discord client/data targeting
- Fails if the sample changes, launches, loads, escapes the worker, or is copied into repository/build output
- Does not place the malware, its bytes, or private derived payloads in Git, GitHub Actions, packages, logs, or public fixtures

### 12.6 Release Gates

A release requires:

- All unit, integration, adversarial, privacy, worker, GUI, and packaging tests passing
- Zero known parser crashes on the maintained regression and fuzz corpora
- No untriaged high-severity dependency vulnerabilities
- Deterministic parser, rule, and scoring identifiers
- Signed release artifacts
- Dependency-license inventory and SBOM
- Repeatable builds where practical
- Clean-machine portable-package validation
- Keyboard navigation, accessibility, DPI, cancellation, and large-result UI validation
- Independent review of scoring-threshold changes

## 13. GitHub Repository

The repository includes:

- Complete application, worker, analyzer, rule, report, and test source
- Detailed README with screenshots, examples, privacy model, architecture, limitations, installation, portable usage, building, testing, and contribution guidance
- Threat model and no-execution security boundary
- Rule-authoring and evidence-language guide
- Versioned JSON schema documentation
- Security policy and private vulnerability-reporting instructions
- GitHub Actions for tests, security checks, SBOM, and release packaging
- Dependency locks and license inventory
- Synthetic benign fixtures
- Local private-regression setup instructions
- Explicit warning not to acquire malware merely to test RunOrNope

The Slyden sample and private extracted artifacts are excluded from Git and all release workflows.

## 14. Version 1 Non-Goals

Version 1 does not:

- Dynamically execute or sandbox samples
- Guarantee safety or provide malware probabilities
- Upload files to reputation services
- Scan user-supplied general archives directly
- Support ELF, Mach-O, APK, Office documents, PDFs, scripts as root inputs, or memory dumps
- Fully deobfuscate arbitrary native, .NET, Java, or JavaScript code
- Recover every NSIS or Inno Setup instruction
- Evaluate environment-dependent installer conditions as though installation occurred
- Replace Microsoft Defender, enterprise EDR, a professional sandbox, or an incident responder

## 15. Research Basis

The design is grounded in:

- Microsoft PE/COFF format documentation
- Microsoft WinTrust and Authenticode documentation
- Microsoft Windows Installer database and table documentation
- Microsoft Job Object and process-mitigation documentation
- VirusTotal YARA-X documentation
- Mandiant capa and capa-rules capability methodology
- Electron ASAR, integrity, and fuse documentation
- Oracle JAR specification
- Current 7-Zip, innoextract, AsmResolver, and PeNet project documentation
- NIST Secure Software Development Framework guidance

Dependency versions, licenses, release provenance, and maintenance status must be revalidated during implementation and before each release.
