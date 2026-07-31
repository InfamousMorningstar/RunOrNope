# Project VOIDLENS report format

Project VOIDLENS exports a validated static-analysis result as deterministic JSON or as a
self-contained, script-free HTML document. Reports never contain submitted sample
bytes. The sample name is a display name, not a path to be opened or resolved.

## JSON envelope

The top-level JSON object has these fields, in this order:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | `runornope-report-1`, the export-envelope version. |
| `reproducibility` | Rules, scoring, threshold, and contract-limit versions used to interpret the result. |
| `privacy` | Evidence mode and, for full evidence, a privacy warning. |
| `verdict` | Analysis status, nullable risk disposition, recommended action, total score, and family contributions. |
| `scanResult` | The complete validated `ScanResult` payload described by `schemas/runornope-report-v1.schema.json`. |

Properties use camel case. Enum values use lower kebab case. Output is UTF-8
without a byte-order mark. The writer adds no timestamp, random identifier,
machine path, or locale-sensitive value, so the same validated result and options
produce identical bytes.

`analysisStatus` and `riskDisposition` are intentionally independent.
`riskDisposition` is `null` when the verdict engine withholds a disposition because
analysis is incomplete, unsupported, or isolation was unavailable. Consumers must
not translate a missing disposition into a favourable result.

The `reproducibility` object records:

- `rulesVersion`, sourced directly from `CapabilityRuleEngine.RulesVersion`;
- `scoringVersion` and `thresholdVersion`, sourced from the evaluated verdict;
- `contractLimits`, including maximum strings, artifacts, observations, findings,
  nested strings, and JSON bytes.

## Privacy modes

The default `redacted` mode masks credential values in contextual forms such as URI
user information, authorization headers, named token/password/API-key assignments,
and PEM private keys. It preserves surrounding evidence, hashes, evidence ids, and
source relationships.

The explicit `full` mode preserves validated evidence text and adds:

> Full evidence may contain credentials, personal data, or sensitive paths.

Redaction is a report privacy control, not a security verdict. It does not change
the source `ScanResult`, completeness, findings, score, or disposition.

## HTML security properties

HTML reports use fixed markup and HTML-encode every dynamic value. Evidence strings,
including strings beginning with `javascript:` or `file:`, are text only. Reports
contain no links, scripts, event handlers, images, frames, forms, objects, embeds,
external fonts, or network resources.

The document declares this Content Security Policy:

```text
default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; media-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'; style-src 'unsafe-inline'
```

The sole CSP exception is the report's fixed inline stylesheet. HTML export-name
suggestions are sanitized leaf names ending in `.runornope.html`; the reporting
library does not create, preview, or shell-open files.

## Validation and compatibility

Both writers invoke `ContractValidator.Validate` before producing output. Unknown
enum values, inconsistent completeness, malformed Unicode, bidi controls,
over-limit content, duplicate ids, and broken evidence references fail the export.
Writers do not repair invalid results or emit partial reports.

Readers should reject unknown major `schemaVersion` values. New optional metadata
requires a new documented envelope version if an older reader could misinterpret
the report's security or verdict semantics.
