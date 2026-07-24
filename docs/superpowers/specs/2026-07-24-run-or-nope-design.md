# RunOrNope Design Specification

**Date:** July 24, 2026  
**Status:** Approved conversational design, pending written-spec review  
**Target:** Windows 10/11 x64  
**Application:** Self-contained .NET 10 WPF desktop application

The supported-OS matrix names exact Windows editions/builds and servicing states;
“Windows 10/11” alone is not a release claim. Unsupported/end-of-servicing hosts
may run the application only as explicitly unverified configurations. The release
matrix must include AppContainer, Job Object, mitigation, WinTrust, MSI read-only,
long-path, and enterprise-policy variants.

.NET 10 is the active LTS release and is supported through November 14, 2028.
RunOrNope must track the current serviced .NET 10 patch and migrate to a supported
LTS before that date. A self-contained deployment does not extend Microsoft
runtime support. The release checklist verifies the target and current patch
against Microsoft's published support policy:
https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core

## 1. Purpose

RunOrNope is a defensive static-analysis application for people deciding whether an unfamiliar Windows executable or installer warrants being run. A user drags in a supported file, RunOrNope dissects it without executing it, and the application explains what capabilities the file appears to implement, what exact evidence supports each conclusion, how complete the analysis was, and what cautious action the user should take.

RunOrNope does not claim to prove a file is safe. Its job is to make static evidence understandable and reproducible.

## 2. Supported Inputs

Version 1 supports:

- Windows PE files: `.exe`, `.dll`, `.scr`, and `.sys`
- Windows Installer databases: `.msi`
- Bounded nested artifacts discovered inside supported inputs:
  - Full v1 analysis: PE/CLR, MSI tables and embedded streams, CAB, ZIP/JAR/class, Electron ASAR, text scripts, and selected high-value configuration files
  - Best-effort v1 extraction adapters: recognized NSIS and Inno Setup versions
  - Identification only unless separately listed above: unknown installer/container versions and other embedded formats

Detection uses file structure and magic bytes rather than filename extensions. Archives supplied directly by the user are outside the version 1 scope. Archives found inside a supported PE or MSI are analyzed as nested artifacts.

Unsupported root formats receive **Unsupported or invalid root format** analysis
status and no risk disposition. Unsupported versions of otherwise recognized
nested packaging receive **Incomplete** status, not a favorable verdict.

“Supports” means that the implementation has a versioned parser, explicit resource
limits, adversarial tests, and completeness semantics for that format. Merely
recognizing a magic value or extracting some strings does not qualify as support.

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
- Send sample hashes, filenames, paths, extracted strings, findings, reports, or
  diagnostics through telemetry, crash reporting, update checks, analytics, or
  dependency features without the separately specified explicit action
- Interpret a parser failure as evidence that a capability is absent

Version 1 has no automatic telemetry, crash upload, analytics, remote rule fetch,
or background update check. The only permitted network operations are the
separately confirmed hash-only VirusTotal lookup and separately confirmed online
signer-trust refresh. Each is implemented outside the worker through a
destination-allowlisted client with redirects disabled, bounded requests and
responses, certificate validation, timeout/cancellation, and an audit entry.

Worker processes suppress interactive crash UI and application-controlled crash
submission. Release testing examines Windows Error Reporting and enterprise dump
policy behavior. The UI claim is limited to what RunOrNope sends; it does not claim
to control OS-, hypervisor-, backup-, synchronization-, or enterprise-managed
telemetry outside the application.

Static parsing occurs in a fresh, disposable AppContainer worker, not in the WPF
process. A restricted token and Job Object alone are not accepted as a security
boundary because neither independently removes network access or contains a
memory-corruption exploit.

Each worker receives:

- A read-only input handle
- A fresh private extraction directory ACLed only to the broker and that worker's unique AppContainer SID
- An AppContainer token with no network, enterprise-authentication, private-network, broad-file, or device capabilities
- No write access to the sample directory
- No inherited handles except required input/output/IPC handles
- A Windows Job Object with kill-on-close, CPU and memory limits, process-count limits, and output quotas
- `ActiveProcessLimit = 1`; worker child-process creation is prohibited
- Process mitigations selected and regression-tested per adapter, including DEP,
  ASLR, CFG where compatible, extension-point disablement, image-load restrictions,
  and prohibition of dynamic code where the parser does not require it
- A strict wall-clock timeout and cancellation path

The broker launches each approved passive native extractor as its own
single-purpose AppContainer worker under a separate Job Object. A parser worker
never launches an extractor or any other child. Adapter executables are selected
from an immutable application manifest and verified against packaged hashes before
launch; a sample-controlled path, filename, environment variable, or configuration
value can never select an executable.

The broker creates the AppContainer profile and ACLs before opening hostile input.
It runs unelevated and refuses analysis if the requested isolation token, capability
set, Job assignment, mitigations, private directory, or handle allowlist cannot be
verified. There is no automatic fallback to an ordinary process. Windows editions
or enterprise policies that prevent the required isolation receive an explicit
**Analysis unavailable: isolation could not be established** result.

The no-network claim is verified both structurally (no AppContainer network
capabilities) and by release tests under IPv4, IPv6, loopback, DNS, proxy, and
private-network scenarios. Job Objects remain resource-governance and lifecycle
controls, not the claimed network sandbox.

Extracted artifacts use generated content-addressed names. Sample-controlled names remain metadata and are never used directly as filesystem paths.

## 4. High-Level Architecture

RunOrNope contains five bounded components:

### 4.1 WPF Desktop UI

The UI accepts a file, starts or cancels analysis, renders progress and findings, provides the optional hash-only VirusTotal lookup, and exports reports. It never parses sample bytes.

### 4.2 Analysis Broker

The broker creates an immutable request, opens the input once with write/delete
sharing denied, records file identity and size, hashes and reads through that same
handle, launches a disposable AppContainer worker, enforces the Job Object and
timeout policy, receives a bounded result DTO, validates it as hostile input, and
disposes of worker artifacts. A path is never reopened after validation. If the
file identity, size, or last-write metadata changes during acquisition, analysis
stops with an incomplete/tampered-input result.

### 4.3 Restricted Analysis Worker

The worker performs format detection, hashing, bounded parsing, recursive artifact
discovery, capability analysis, and rule evaluation. A crash, timeout, limit
violation, or parser rejection becomes structured incompleteness evidence. Worker
stdout, stderr, exception text, parser diagnostics, and DTO strings are
sample-influenced and receive the same length, encoding, and rendering controls as
sample content.

### 4.4 Evidence and Verdict Engine

The engine converts observations into transparent capability findings, tracks
completeness and confidence independently from severity, caps correlated evidence
families, and produces a cautious risk disposition plus an independent analysis
status.

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

Default Deep Scan policy limits:

- Maximum recursion depth: 5
- Maximum children per artifact: 1,000
- Maximum total artifacts: 5,000
- Maximum single materialized child: 256 MiB
- Maximum total materialized bytes: the lower of 2 GiB or 10 times the input size
- Maximum expansion ratio per member: 200 times
- Maximum aggregate expansion ratio: 50 times
- Adapter timeouts: 30 to 120 seconds, selected by format
- Adapter memory limits: 256 MiB to 1 GiB, selected by format

These are user-reducible defaults, not user-expandable security ceilings. A
separately versioned hard-ceiling policy bounds recursion, artifacts, bytes,
memory, CPU, wall time, path/string lengths, table rows, findings, IPC payloads,
and report size. The broker checks free disk space before and during extraction,
uses quotas rather than trusting archive metadata, and cancels before reserve
space is exhausted. Hitting any completeness-affecting limit records
`TruncatedByPolicy` on the affected artifact and forces an incomplete-analysis
disclosure.

Extraction rejects absolute, drive, UNC, device, traversal, alternate-data-stream, reserved-device, case-collision, trailing-dot, and trailing-space paths. It does not follow symlinks, hard links, mount points, junctions, or other reparse points.

Archive/container adapters parse member metadata first and stream bounded content
where possible. They never preallocate from sample-declared sizes. Every output
file is created beneath the already-open private directory using generated names,
with reparse-point checks on every directory handle. Temporary files are opened
delete-on-close where compatible and are removed by the broker after worker
termination. Cleanup failure is reported and retried on next launch.

Deduplication prevents repeated analysis but does not bypass accounting: every
logical member, compressed byte, expanded byte, edge, and parser attempt counts
toward its applicable quota even when its content hash was seen earlier.

## 6. Analysis Pipeline

### 6.1 Identity and Trust

RunOrNope records:

- SHA-256 as the identity key; optional SHA-1 and MD5 are labeled legacy
  interoperability values and are never used for trust, deduplication, or verdicts
- Actual format and architecture
- File size and timestamps, clearly labeled as untrusted metadata
- Version-resource claims
- Manifest and requested execution level
- Authenticode certificate-table structure
- Windows trust verification result and exact policy/error code
- Embedded versus catalog signature
- Every discovered signature, digest validity, chain state, signer, issuer,
  thumbprints, RFC 3161 or legacy countersignature timestamp state, and revocation
  result
- Verification mode, verification time, Windows trust-policy configuration, root
  store context, catalog source, and whether only local/cache data was used

Signature presence is not signature validity. A valid signature is identity and integrity evidence, not proof of benign behavior. Unsigned software is not automatically suspicious.

Default local analysis performs cache-only, noninteractive trust verification and
must not trigger automatic root, AIA, CRL, OCSP, timestamp, catalog, or reputation
retrieval. An unavailable revocation or chain result is **Indeterminate/offline**,
not valid or invalid. A separately confirmed **Refresh signer trust online** action
may perform certificate-network retrieval; it discloses that no sample bytes or
sample URLs are sent, records the network mode, and remains separate from static
behavior evidence.

The implementation uses Windows trust APIs for the platform trust verdict rather
than inferring validity from certificate extraction. It enumerates multiple
signatures, distinguishes embedded and catalog trust, closes provider state, and
tests strict Authenticode padding behavior. Catalog trust is machine/store
context-dependent and is reported as such; it is not a portable property of the
file alone. A historical timestamp may preserve signing-time validity while
current revocation or policy state remains separately reported.

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

MSI packages are opened only inside the AppContainer MSI worker through the Windows
Installer database API using `MSIDBOPEN_READONLY`. No install session is created,
no product state is queried as evidence of package behavior, and no API that
applies transforms, patches, advertisements, repairs, or installations is called.
If read-only MSI database access cannot operate under the required isolation on a
supported Windows configuration, MSI analysis fails closed; the broker does not
retry outside AppContainer.

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
- Package signature state separately from `MsiDigitalSignature`/
  `MsiDigitalCertificate` coverage of external media

Custom-action type bits are decoded into action kind, source, target, timing, rollback/commit/deferred state, impersonation context, potential elevation, sequence, and condition. A custom action is legitimate MSI functionality and is not inherently malicious.

Embedded streams and cabinets become child artifacts and are recursively analyzed. Missing external cabinets, transforms, patches, or sources force an incomplete result. MSI installation, package sessions, UI preview, repair, patching, and custom-action invocation are prohibited.

Conditions and formatted properties are reported as static expressions unless they
can be resolved solely from immutable package data. RunOrNope does not pretend to
evaluate machine-, user-, feature-selection-, policy-, or install-state-dependent
branches. Deferred/no-impersonate custom actions are reported as potential
elevated execution only when sequencing and package context support that
interpretation.

The outer MSI signature does not by itself establish coverage of external
cabinets, transforms, downloaded sources, or later patches. Coverage is presented
per object. Missing referenced media prevents a complete payload verdict even
when the database signature is valid.

### 6.5 Installer and Container Analysis

Installer recognition combines multiple structural signals and preserves every detected layer.

- Recognized NSIS archive payloads may use a specifically versioned, packaged,
  hash-verified 7-Zip backend in its own AppContainer worker. “Current” is not a
  version requirement; adapter version, supported format range, license, upstream
  provenance, and security-review date are release metadata.
- Inno Setup may use a specifically versioned, packaged, hash-verified
  `innoextract` backend under the same rules when the format version is explicitly
  supported. Newer, ambiguous, or rejected versions are reported as unparsed.
- Electron ASAR uses a custom bounded managed reader based on the documented format. It caps header size, JSON depth, entry count, offsets, lengths, and logical path lengths.
- CAB extraction uses one selected, documented, bounded implementation in its own
  worker. The implementation choice cannot remain “parser or API” at release
  because its security properties and test oracle must be known.
- Java JARs use bounded ZIP parsing with traversal, entry, depth, size, and ratio protections.

The application never invokes installer switches, including switches advertised as extraction or help modes, because installer initialization may still execute code.

Adapters receive only generated paths/handles and fixed arguments from the broker.
No sample-controlled switch, response file, environment variable, working
directory, DLL search path, plugin path, locale path, or output path reaches an
adapter command line. Adapter output is not trusted merely because the process
exited successfully; the broker independently validates every returned path,
size, count, and content hash.

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

- Manifest, main class, class path, multi-release entries, modules, service
  providers, and per-entry JAR signature/digest coverage
- Constant pools, class hierarchy, methods, descriptors, annotations, bootstrap methods, invokedynamic, method handles, strings, code references, and exception tables
- Native/JNA loading, process spawning, networking, filesystem traversal, archives, browser/Discord paths, DPAPI/NSS access, database access, webcam/screen APIs, and WebSockets

Application classes are separated from bundled dependencies using package clustering, Maven metadata, known hashes, manifests, call direction, and shaded-library signatures. Library capability alone cannot become confirmed application behavior.

JAR signing is reported as integrity/identity evidence with explicit unsigned,
partially signed, mixed-signer, invalid-digest, and unsupported-algorithm states.
The presence of `META-INF` signature files is not treated as successful
verification. Multi-release entries are analyzed under their applicable Java
version and cannot silently replace a base-class finding.

Surviving method names, strings, imports, constant-pool entries, and YARA matches
are observations, not confirmed behavior. **Confirmed static implementation**
requires a parsed implementation body or equivalent data flow that performs the
operation in application-linked code. An unresolved `invokedynamic`, reflection,
native transition, dynamic import, or encrypted dispatcher lowers reachability or
linkage confidence rather than being guessed.

Electron fuse and ASAR-integrity observations are version-sensitive. If the
Electron version or fuse layout cannot be reliably identified, the state is
**Unknown**, not disabled. A declared ASAR integrity hash is verified against the
corresponding bytes before it is reported as valid.

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

YARA-X runs in the AppContainer worker with time and input limits. Rules are compiled and validated before release. A YARA match is labeled a rule detection, not proof of a malware family, capability execution, or incident outcome.

Release rule packs are immutable, signed/versioned application inputs. They cannot
use remote includes, arbitrary user paths, or unreviewed modules. Rule compilation,
module parsing, and matching all occur in the AppContainer worker. A rule timeout,
engine error, unsupported module, or skipped artifact is completeness evidence.
Community rule names and metadata are untrusted display text and do not determine
severity. License and provenance are enforced in CI.

User-supplied rules are a post-v1 feature. If later added, they require a distinct
trust model, stricter quotas, an explicit namespace, and results visually separated
from the curated release rules.

### 6.9 Optional VirusTotal Lookup

Local analysis performs no network access.

The separate **Look up this SHA-256 on VirusTotal** action:

- Requires explicit user activation and confirmation
- Displays the exact hash, endpoint, recipient, and privacy consequence before
  sending: a hash can identify a unique/private file and the lookup discloses
  interest in or possession of that hash to the service
- Sends only the SHA-256
- Never uploads file bytes
- Stores an API key only through an appropriate local secret mechanism
- Keeps reputation results separate from local static evidence
- Records lookup time, response provenance, API/error state, and cache age
- Never retries, follows a service-provided URL, or submits another artifact
  without a new bounded request under the documented API contract

The UI must not imply that “hash only” is anonymous. A missing hash report is
**Unknown**, not evidence of benignness. Vendor counts are displayed with scan
time and denominator and cannot independently produce a `High-risk` or favorable
local verdict.

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

Recommended actions come from a small reviewed taxonomy and never promise that a
control makes a file safe. **High-risk static indicators** recommends not running
the file and verifying provenance or escalating to a qualified reviewer.
**Caution warranted** recommends obtaining the software from an authoritative
source, verifying publisher/hash through an independent channel, and scanning with
current endpoint protection. A favorable result still carries the mandatory
non-guarantee wording. RunOrNope v1 does not delete, quarantine, move, rename,
unblock, strip Mark-of-the-Web, change ACLs, or offer a **Run anyway** action.

Technical users can expand cards to view imports, methods, strings, MSI rows, rule matches, byte offsets, call relationships, and artifact hashes.

## 9. Verdict Model

Risk dispositions are:

- **High-risk static indicators**
- **Caution warranted**
- **Few material static concerns identified**

Analysis status is independent and always displayed:

- **Complete within the declared v1 policy**
- **Incomplete**
- **Unsupported or invalid root format**
- **Analysis unavailable: isolation could not be established**

A file can simultaneously have **High-risk static indicators** and **Incomplete**
analysis. Incompleteness never lowers a risk disposition, suppresses already
established findings, or becomes a favorable result. An unsupported/unavailable
root receives no risk disposition.

The verdict engine tracks three dimensions independently:

- Parse confidence
- Evidence confidence
- Potential risk severity

Evidence is grouped into independent families. Each family has a capped contribution so correlated findings cannot dominate the outcome. Strong behavioral evidence or multiple reinforcing independent families are required for a high-risk result.

Weak context such as unsigned status, entropy, timestamp anomalies, uncommon section names, low prevalence, or packing cannot independently produce a high-risk verdict.

Positive evidence such as a trusted signature may reduce identity uncertainty but cannot erase behavioral findings.

Every report exposes verdict contributions, correlated-family caps,
countervailing facts, rule/scoring versions, threshold version, and completeness
state. There are no safety guarantees or malware probability percentages.

The scoring engine uses integer/rational versioned weights, deterministic ordering,
and documented saturation rules. Negative or “benign” evidence can reduce only the
specific uncertainty it addresses; it cannot subtract from an unrelated behavioral
finding. Parser errors, unavailable dependencies, missing MSI media, encrypted
dispatch, and unsupported nested formats contribute no negative points.

Before v1 release, thresholds are frozen against a held-out corpus and an explicit
false-positive budget. Any later rule, weight, parser, trust-policy, or threshold
change increments a scoring/rules version and produces a before/after regression
report. A YARA family name, signer reputation, filename, extension, entropy,
timestamp, or single capability string cannot alone trigger **High-risk static
indicators**.

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

- **RunOrNope did not invoke or install the sample**
- **RunOrNope did not upload file bytes**
- Worker isolation status and any isolation/policy failure
- Whether any optional network action occurred
- Whether a hash or certificate identifier was disclosed by an optional network action
- SHA-256
- Analysis completeness
- Signer status
- Strongest evidence
- Unsupported or unresolved content
- Parser, rules, and scoring versions

## 11. Reports

HTML reports are portable, self-contained, and use native HTML disclosure elements
for interaction; v1 reports contain no JavaScript. They include a restrictive
Content Security Policy (`default-src 'none'`, with only the exact required local
style policy), no remote fonts/images/styles, no forms, no active content, no
automatic refresh, and no clickable sample-derived URI. They mirror the UI's
summary and expandable evidence.

All report values are constructed through typed encoders; sample-derived strings
are never concatenated into markup, attributes, CSS, filenames, paths, log
templates, or JSON fragments. Control characters, bidirectional controls,
unpaired surrogates, confusable path separators, and overlong values are escaped
or visibly annotated while preserving a bounded byte/Unicode representation for
technical review. Formula-prefix defenses are applied if CSV or spreadsheet export
is ever added.

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

Reports never embed a complete submitted executable, complete extracted payload,
or reconstructable binary. Bounded byte/string excerpts may appear only when
needed as evidence, are size-limited and escaped, and are covered by the report
privacy warning and disclosure mode.

Reports are themselves potentially sensitive. By default they omit the source
directory, username-bearing absolute paths, API keys, authorization headers,
cookies, tokens, private keys, full document contents, and unbounded strings.
Secret-like values are redacted with type, length, and a nonreversible report-local
identifier. The user may explicitly opt into a **Full technical evidence** report
after a warning; this never changes the prohibition on complete or reconstructable
payloads, and the report records the disclosure mode.

Export uses a user-selected destination, a fixed safe extension, a
RunOrNope-generated filename, and create-new/explicit-overwrite semantics. A
sample-controlled product name or original filename is display metadata only.
Reports state that opening or sharing them may disclose filenames, infrastructure,
signers, and security findings. Diagnostic logs follow the same redaction and
length policy and never contain sample bytes by default.

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

Fuzzing covers both in-process parser libraries and the production AppContainer
adapter boundary. Seed corpora include valid minimal structures, boundary cases,
and synthetic malformed files; no private malware is uploaded to hosted fuzzing.
Every discovered crash/hang receives a minimized non-sensitive reproducer where
licensing and safety permit. Parser/adapter upgrades replay the complete regression
corpus before merge.

The broker's hostile-result boundary is fuzzed independently: malformed lengths,
duplicate IDs, invalid graph edges, excessive nesting, invalid Unicode, control
characters, HTML/JSON payloads, huge diagnostics, and inconsistent completeness
claims must be rejected without affecting the UI process.

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

Evaluation labels record their provenance and uncertainty. “Malicious” corpora
must not rely solely on antivirus consensus, and “benign” corpora must not rely
solely on a valid signature. Threshold selection uses a development set; final
metrics use a held-out set that cannot be used to tune rules. Results publish
sample counts and confidence intervals, not only aggregate percentages.

Required benign challenge sets include unsigned utilities, administrative and
remote-management tools, debuggers, accessibility software, game launchers/mods,
packers/protectors, installers with legitimate elevated custom actions,
self-contained .NET applications, Electron applications, and enterprise software.

### 12.4 No-Execution and Privacy Tests

Tests verify the following requirements through complementary controls and
observations:

- Samples and embedded artifacts are never invoked as code, mapped as executable
  images, installed, or loaded through managed/native module-loading APIs
- No installer, repair, registration, custom action, preview, script, Java, Node, Electron, or shell path is invoked
- Managed worker child-process creation is blocked
- Local scans create no DNS requests, outbound connections, or uploads
- VirusTotal sends only the explicitly confirmed SHA-256
- Extracted bytes remain within the worker's private directory
- Worker limits, restricted identity, cancellation, and kill-on-close function correctly
- A hostile worker cannot reach loopback, LAN, DNS, IPv4/IPv6 Internet, configured
  proxies, named pipes outside the allowlist, user profile data, registry secrets,
  devices, clipboard, window station/UI, or broker handles outside the allowlist
- Each native adapter is limited to one process and cannot influence executable,
  DLL/plugin, configuration, locale, or output-path selection with sample data
- Report generation neutralizes markup, URI, CSS, bidirectional-text, control
  character, oversized-value, and JSON injection cases and applies default
  redaction
- The release package contains no test malware, extracted payload, API key,
  developer path, private report, or unapproved rule

No single test “proves” the absence of execution or network behavior. Release
evidence combines process/thread/image-load telemetry, child-process denial,
AppContainer capability inspection, filesystem/registry monitoring, packet and
DNS capture, loopback/private-network listeners, canary executables and DLLs, and
negative tests that deliberately attempt each prohibited operation. Tests run on
every supported Windows build class, not only a developer workstation.

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

This private sample is not a release gate on machines where it is absent and is
not used to tune a special-case verdict. Public CI uses synthetic fixtures that
exercise the same parser/evidence paths without reproducing private malicious
content. The local harness records only approved hashes and redacted assertions,
requires an explicit opt-in environment flag, and refuses to fetch the sample.

### 12.6 Release Gates

A release requires:

- All unit, integration, adversarial, privacy, worker, GUI, and packaging tests passing
- Zero known parser crashes on the maintained regression and fuzz corpora
- No untriaged high-severity dependency vulnerabilities
- Deterministic parser, rule, and scoring identifiers
- Signed release artifacts
- Dependency-license inventory and SBOM
- Repeatable builds where practical
- A clean-room rebuild comparison or documented explanation of every
  nondeterministic output
- Source revision, toolchain, SDK/runtime, adapter, rules, and dependency digests
  embedded in release provenance
- Clean-machine portable-package validation
- Keyboard navigation, accessibility, DPI, cancellation, and large-result UI validation
- Independent review of scoring-threshold changes
- Verification that all workers fail closed when AppContainer creation,
  mitigations, Job assignment, ACLs, or handle restrictions are denied
- Verification that the supported Windows build/edition matrix is still serviced
  and that the bundled .NET runtime remains supported
- Signing-key custody, rotation, revocation, and incident-recovery procedure tested

“Zero known parser crashes” means zero reproducible, untriaged crashes in supported
code paths. It does not mean the parsers are vulnerability-free. Every parser
crash, hang, memory-limit kill, malformed DTO, and sandbox-policy failure is a
security defect until triaged and a completeness event for the affected scan.

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

Repository and release controls include:

- Protected default and release branches, required review and status checks, no
  force pushes, and two-person approval for release/signing workflow changes
- Least-privilege GitHub Actions permissions declared per job
- Third-party actions pinned by immutable commit SHA and reviewed before updates
- No untrusted pull-request code executed in a context that has release secrets,
  signing keys, writable package permissions, or persistent self-hosted runners
- Ephemeral hosted runners for untrusted contributions; release jobs consume only
  reviewed source and reproducibly identified build inputs
- Secret scanning, dependency review, code scanning, provenance/attestation, and
  artifact-digest verification
- Release creation only from a protected, annotated tag whose commit passed the
  release gates
- Published checksums, SBOM, provenance, signing certificate/key identifier, and
  verification instructions next to every artifact
- A security advisory and revocation process for compromised releases, parser
  vulnerabilities, malicious rule updates, and signing-key compromise

Version 1 has no in-application auto-updater. Users obtain updates through the
documented release channel and verify the signed release and digest. This avoids
introducing a privileged network/update execution path before a separately
threat-modeled update design exists.

Any future updater must use a signed, versioned update manifest anchored in keys
shipped with the application; HTTPS alone is insufficient. It must resist rollback,
freeze, mix-and-match, and mirror compromise; verify manifest and artifact before
execution; support signing-key rotation/revocation; never accept a package selected
by sample content; and require its own architecture and penetration review.

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

## 16. Residual Risks and Trust Assumptions

The design reduces risk; it cannot make hostile parsing risk-free. Public
documentation and the threat model explicitly retain these residual risks:

- A parser, native adapter, .NET runtime, Windows API, AppContainer, broker, or
  kernel vulnerability may permit code execution or sandbox escape.
- AppContainer containment depends on the supported Windows build, configured
  mitigations, ACL correctness, handle discipline, and absence of dangerous broker
  services or enterprise policy exceptions.
- Static analysis cannot reliably resolve every packed, encrypted, reflective,
  downloaded, environment-dependent, native, or deliberately obfuscated behavior.
- A valid platform trust result depends on verification time, machine trust stores,
  policy, revocation availability, and catalog context and may change later.
- Resource ceilings allow denial of analysis by forcing an incomplete result; they
  intentionally prefer availability loss over unsafe extraction.
- Pinned third-party parsers, YARA-X, rules, GitHub Actions, the build toolchain,
  signing infrastructure, and dependencies remain supply-chain trust anchors.
- Full-evidence reports may contain sensitive indicators or bounded hostile text
  despite encoding and redaction controls.
- RunOrNope cannot control operating-system, endpoint-security, backup,
  synchronization, hypervisor, or enterprise telemetry outside its own processes.
- A user can disregard the recommendation, obtain a different file after scanning,
  or run a modified/time-dependent/downloader sample whose behavior was absent from
  the scanned bytes.

These are disclosed as limitations, not converted into low-confidence findings or
hidden behind a favorable verdict.
