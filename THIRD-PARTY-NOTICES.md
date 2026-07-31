# Third-Party Notices

Project VOIDLENS is distributed under the MIT License (see `LICENSE`). It incorporates,
and plans to incorporate, the third-party components listed below. Each is used
under its own license; those licenses and their attribution requirements are
preserved here.

Licenses were verified against each component's authoritative source on
**2026-07-24**. Versions and license terms must be re-verified before every
release, and any component whose license changes (as FluentAssertions did at
version 8.0) must be re-evaluated for continued inclusion.

## Bundled at runtime (ship in the application)

| Component | Version | License | Source |
| --- | --- | --- | --- |
| AsmResolver.PE | 6.0.0 | MIT | https://github.com/Washi1337/AsmResolver |
| JsonSchema.Net (json-everything) | 9.3.0 | MIT | https://github.com/json-everything/json-everything |

## Build- and test-only (not distributed in the application)

| Component | Version | License | Source |
| --- | --- | --- | --- |
| AwesomeAssertions | 9.5.0 | Apache-2.0 | https://github.com/AwesomeAssertions/AwesomeAssertions |
| xunit.v3 | 3.2.2 | Apache-2.0 | https://github.com/xunit/xunit |
| xunit.runner.visualstudio | 3.1.5 | Apache-2.0 | https://github.com/xunit/visualstudio.xunit |
| Microsoft.NET.Test.Sdk | 18.0.1 | MIT | https://github.com/microsoft/vstest |

> AwesomeAssertions replaced FluentAssertions, whose 8.x releases require a paid
> commercial license (free only for open-source / non-commercial use).
> AwesomeAssertions is a community fork of the last Apache-2.0 FluentAssertions
> line and is free for all use.

## Planned security integrations (NOT yet bundled)

These are approved for inclusion by license and are staged for future slices.
They are documented here so their licenses are settled before any code or binary
is vendored. None of them is present in the repository yet.

| Component | License | Free commercial use | Notes | Source |
| --- | --- | --- | --- | --- |
| YARA-X | BSD-3-Clause | Yes | Scanning engine + curated, versioned rule packs. Rule packs are separate works; each pack's own license and provenance must be recorded before inclusion. | https://github.com/VirusTotal/yara-x |
| innoextract | zlib | Yes | Inno Setup extraction backend, run as an isolated adapter. | https://github.com/dscharrer/innoextract |
| 7-Zip | LGPL-2.1-or-later, with BSD-licensed parts and the unRAR restriction | Yes | Archive extraction backend, run as an isolated adapter. The unRAR clause only forbids recreating the RAR *compression* algorithm; it does not affect extraction use or redistribution. LGPL is satisfied by invoking 7-Zip as a separate, unmodified executable. | https://www.7-zip.org/ |

Detection rules that identify specific malware families (for example
information-stealer families) are carried only as **signatures/rules**, never as
copies of the malware itself. Every rule pack must ship under a permissive,
clearly stated license with recorded provenance; community rule names and
metadata are treated as untrusted display text.
