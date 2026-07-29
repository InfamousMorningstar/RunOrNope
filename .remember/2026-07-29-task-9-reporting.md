# Task 9 reporting handoff — July 29, 2026

Done:

- Wrote `docs/superpowers/specs/2026-07-29-safe-reporting-slice-design.md`.
- Added deterministic JSON report envelopes and self-contained script-free HTML.
- Added default contextual secret redaction and explicit full-evidence warnings.
- Wired report metadata directly to `CapabilityRuleEngine.RulesVersion`.
- Added injection, CSP, validation, UTF-8, filename, redaction, determinism, and
  verdict-axis tests.
- Documented the envelope and privacy behavior in `docs/REPORT_SCHEMA.md`.

Verification:

- `& .\.tools\dotnet\dotnet.exe test -c Release`
- 185 unit, 45 security, and 6 integration tests passed before the final
  export-name scalar-cap regression was added; rerun before commit.

Next:

- Task 10 is the WPF scan workflow in `src/RunOrNope.App/`.
- Keep the App presentation-only and never preview or shell-open sample-controlled
  content.
