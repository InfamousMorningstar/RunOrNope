# Safe Reporting Slice — Design

**Date:** July 29, 2026
**Status:** Approved requirements, implementation pending
**Parent design:** `docs/superpowers/specs/2026-07-24-run-or-nope-design.md`
**Plan task:** Task 9 — Script-Free Reports and Privacy Controls

## 1. Purpose

Export a validated `ScanResult` as deterministic JSON or a self-contained,
script-free HTML report without turning attacker-controlled report text into active
content or leaking common secrets by default. Reports preserve the distinction
between risk disposition and analysis completeness and include enough version and
limit metadata to reproduce how the result was interpreted.

## 2. Scope

In scope:

- A versioned JSON report envelope containing a validated `ScanResult`, its verdict,
  privacy mode, and reproducibility metadata.
- A self-contained HTML rendering of the same projected data.
- Typed text handling, restrictive CSP, safe suggested export names, and default
  redaction of secret-like values.
- An explicit full-evidence mode whose output carries a privacy warning.
- Documentation of the exported JSON shape and privacy behavior.

Out of scope: changes to `ScanResult`, its validator, the JSON schema owned by the
contracts slice, `ScoringPolicy`, `VerdictEngine`, analyzer output, browser preview,
report signing, network resources, and application export UI.

The writers consume in-memory, already bounded contract objects only. They never
read, reopen, preview, execute, resolve, upload, or otherwise act on the submitted
sample or on strings contained in it.

## 3. Public API and report model

`RunOrNope.Reporting` exposes:

```csharp
public enum ReportEvidenceMode { Redacted, Full }

public sealed record ReportOptions(ReportEvidenceMode EvidenceMode)
{
    public static ReportOptions Default { get; } =
        new(ReportEvidenceMode.Redacted);
}

public static class JsonReportWriter
{
    public static byte[] Write(ScanResult result, ReportOptions? options = null);
}

public static class HtmlReportWriter
{
    public static byte[] Write(ScanResult result, ReportOptions? options = null);
    public static string SuggestFileName(string sampleName);
}
```

Both `Write` methods call `ContractValidator.Validate` before deriving or rendering
anything. Invalid, over-limit, bidi-containing, or malformed-Unicode results fail
with `ContractValidationException`; writers do not repair hostile contract data or
turn validation failures into partial favourable reports.

JSON is a versioned envelope rather than a change to the stable `ScanResult`:

```json
{
  "schemaVersion": "runornope-report-1",
  "reproducibility": {
    "rulesVersion": "capability-rules-1",
    "contractLimits": {
      "maxStringLength": 16384,
      "maxArtifacts": 4096,
      "maxObservations": 65536,
      "maxFindings": 4096,
      "maxNestedStrings": 4096,
      "maxJsonBytes": 33554432
    }
  },
  "privacy": {
    "evidenceMode": "redacted",
    "warning": null
  },
  "verdict": {
    "analysisStatus": "complete",
    "riskDisposition": "caution-warranted",
    "recommendedAction": "exercise-caution",
    "score": 25
  },
  "scanResult": {}
}
```

The real `scanResult` is the complete projected contract object; the abbreviated
object above documents nesting only. Enum values use lower kebab case and property
names use camel case. The envelope contains no generation timestamp, random id, or
machine-specific path, so identical input and options produce identical UTF-8
bytes. `rulesVersion` is read directly from
`CapabilityRuleEngine.RulesVersion`; Reporting takes a project reference on Rules
so this metadata cannot drift from the engine.

`VerdictEngine.Evaluate` supplies the verdict block. Analysis status and nullable
risk disposition remain separate fields. No scoring threshold or verdict behavior
changes in this slice.

## 4. Privacy projection and redaction

`RedactionPolicy` recursively projects every report-visible string before either
writer serializes it. It does not mutate `ScanResult`, alter ids, hashes, enum
values, numeric values, or collection order.

Default mode replaces only the sensitive value within common credential forms
with the literal `[REDACTED]`, preserving enough context to explain the evidence:

- URI user information (`scheme://user:secret@host`);
- query or form-style values whose case-insensitive key is `token`, `access_token`,
  `api_key`, `apikey`, `secret`, `password`, or `passwd`;
- assignment forms for the same keys (`password=...`, `token: ...`);
- `Authorization: Bearer ...` and `Authorization: Basic ...`;
- PEM private-key bodies between `BEGIN ... PRIVATE KEY` and the matching end marker.

Detection is bounded, ordinal/culture-invariant, and linear over each already
bounded string. Redaction never recognizes, dereferences, or canonicalizes a URI:
`javascript:`, `file:`, UNC paths, and ordinary URLs remain inert report text.
SHA-256 artifact hashes are not secrets and remain intact.

`Full` mode preserves validated strings verbatim but adds the fixed warning
`Full evidence may contain credentials, personal data, or sensitive paths.` to
both JSON and the top of HTML. Choosing this mode is explicit through
`ReportOptions`; there is no environment variable or implicit fallback that enables
it.

**Superseded:** removing every substring that resembles a long token was rejected.
It would hide hashes and evidence ids, making reports irreproducible and weakening
provenance. Redaction is therefore limited to values with credential-bearing
context. A second rejected approach wrote a redacted `ScanResult`; that could
invalidate observation references and SHA-256 fields. The projection keeps the
contract structure and redacts only free-text fields.

## 5. JSON writer

`JsonReportWriter` creates the envelope in a fixed property order and serializes
with `System.Text.Json` using UTF-8, camel-case properties, lower-kebab-case string
enums, no indentation, and strict escaping. The output begins directly with `{`
and has no UTF-8 BOM.

The writer uses a bounded stream. The final export is limited to
`ContractLimits.MaxJsonBytes`; exceeding it throws
`ContractValidationException`. Duplicate artifact ids, observation ids, or finding
evidence ids are rejected by the existing validator rather than silently collapsed.
No sample bytes or original sample path exist in the report model and therefore
cannot be embedded.

The existing `schemas/runornope-report-v1.schema.json` describes the bare contract
shape and remains unchanged. `docs/REPORT_SCHEMA.md` documents the Task 9 envelope
and explicitly identifies `scanResult` as that validated v1 contract payload.

## 6. HTML writer and injection boundary

HTML is generated from fixed markup and encoded text nodes only. `SafeText` performs
HTML encoding for every dynamic string. Dynamic values are never inserted into tag
names, raw markup, comments, style blocks, URLs, event attributes, or CSS.

The document:

- is complete UTF-8 HTML with no BOM and no external resources;
- contains no `<script>`, `<iframe>`, `<object>`, `<embed>`, `<base>`, form, active
  media, link, image, or anchor elements;
- contains no event-handler attributes and no generated `href`, `src`, or `style`
  attributes;
- uses a fixed inline `<style>` block for readable print and screen layout;
- emits this CSP as an early `<meta http-equiv="Content-Security-Policy">`:

```text
default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none';
font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none';
form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'
```

The report renders summary/verdict, reproducibility and privacy metadata, artifact
inventory, findings with exact observation ids and benign explanations, observation
details, limitations, countervailing facts, completeness, and hashes. Empty
sections state `None reported`; they do not imply analysis completeness.
`javascript:` and `file:` substrings are rendered as encoded text with no clickable
element or URI-valued attribute.

`SuggestFileName` takes only the last file-name component, replaces Windows-invalid
characters, controls, separators, trailing dots/spaces, and reserved device names,
caps the stem to 120 Unicode scalars without splitting surrogate pairs, substitutes
`sample` for an empty result, and appends `.runornope.html`. It is a suggestion only;
this slice does not create a file or resolve a path.

**Superseded:** data-URI assets and clickable evidence links were rejected. Even
self-contained active URLs unnecessarily enlarge the injection surface, and report
evidence does not need navigation. An inline style block is retained for usability
and is the CSP's only exception.

## 7. Invalid text handling

The contract boundary accepts .NET strings, not raw report bytes. Unpaired
surrogates—the in-memory analogue of invalid Unicode input—are rejected by
`ContractValidator` before rendering. Writer output is produced by the framework
UTF-8 encoder and tests decode it with a throwing UTF-8 decoder, proving that both
formats contain valid UTF-8. Bidi formatting/isolate controls are likewise rejected,
not stripped, so a report can never disguise their presence as trustworthy text.

## 8. Testing

Tests are written first and observed failing for the missing writer behavior.
Synthetic benign contract objects only are used; no submitted sample is opened or
previewed.

- **Validation gate:** both writers reject a bidi control, an unpaired surrogate, an
  over-limit string, duplicate artifact ids, duplicate observation ids, duplicate
  finding evidence ids, and unresolved evidence references.
- **HTML element injection:** hostile sample/evidence text containing
  `<script>`, `<img onerror>`, closing tags, comments, and `&` appears only as
  encoded text; parsing the result finds none of the injected elements.
- **HTML attribute/URI injection:** quotes, backticks, `javascript:`, `file:`, UNC
  paths, and hostile filenames create no dynamic attributes, links, or active
  elements.
- **CSP and self-containment:** the exact restrictive CSP is present before report
  content; the document contains no scripts, frames, forms, objects, embeds, images,
  external resources, event handlers, or URL-valued dynamic attributes. The only
  permitted inline active-type content is the fixed style block.
- **Safe export name:** traversal, separators, control characters, Windows-invalid
  characters, trailing dots/spaces, reserved device names, an empty name, emoji,
  and an oversized name produce a bounded leaf filename ending in
  `.runornope.html`.
- **Default redaction:** URI credentials, bearer/basic authorization, named query
  tokens, assignment-form passwords/API keys, and PEM private keys are masked in
  both formats; surrounding evidence remains visible; SHA-256 hashes and unrelated
  long identifiers remain visible.
- **Full evidence:** explicit full mode preserves secret-like text and emits the
  privacy warning in both formats; default mode is redacted.
- **JSON shape:** the envelope uses literal schema/rules versions, includes every
  contract limit, verdict axes, hashes, completeness, findings, observation
  provenance, benign explanations, limitations, and countervailing facts; it
  embeds no path or sample bytes.
- **Rules-version wiring:** changing the engine's `RulesVersion` changes both JSON
  and HTML metadata because neither writer owns a duplicate value.
- **Determinism:** repeated writes of the same result/options are byte-for-byte
  identical; collection and evidence order is preserved.
- **Encoding and bounds:** both outputs round-trip through strict UTF-8 decoding,
  including non-BMP text; neither has a BOM; JSON rejects output beyond the report
  byte cap.
- **Verdict integrity:** complete and incomplete fixtures retain independent
  analysis status and nullable disposition exactly as returned by
  `VerdictEngine`; no reporting code alters scoring.

## 9. Files and dependencies

- `src/RunOrNope.Reporting/JsonReportWriter.cs` — deterministic envelope writer.
- `src/RunOrNope.Reporting/HtmlReportWriter.cs` — inert HTML rendering and export
  name suggestion.
- `src/RunOrNope.Reporting/RedactionPolicy.cs` — bounded privacy projection.
- `src/RunOrNope.Reporting/SafeText.cs` — typed HTML text encoding.
- `src/RunOrNope.Reporting/ReportModels.cs` — report options and internal envelope.
- `src/RunOrNope.Reporting/RunOrNope.Reporting.csproj` — add Rules reference.
- `tests/RunOrNope.UnitTests/Reporting/*.cs` — injection, redaction, JSON, encoding,
  determinism, and validation tests.
- `tests/RunOrNope.UnitTests/RunOrNope.UnitTests.csproj` — add Reporting reference.
- `docs/REPORT_SCHEMA.md` — envelope, privacy modes, CSP, and reproducibility fields.

No package, shared contract, solution, analyzer, scoring-policy, or verdict-engine
change is required.
