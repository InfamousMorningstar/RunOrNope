using System.Collections.Immutable;
using System.Globalization;
using System.Text;
using RunOrNope.Contracts;

namespace RunOrNope.Analyzers.Pe;

/// <summary>
/// Translates a <see cref="PeAnalysisResult"/> into the bounded
/// <see cref="ScanResult"/> evidence contract. Pure and deterministic: given the
/// same analysis, hash, size, and support flag it always emits the same result.
/// This slice emits structural observations only — never a capability finding —
/// so it never asserts a risk disposition a rules engine has not yet earned.
/// </summary>
public static class PeScanResultMapper
{
    private const string RootArtifactId = ScanArtifacts.RootId;
    private const uint MemExecute = 0x2000_0000;
    private const uint MemRead = 0x4000_0000;
    private const uint MemWrite = 0x8000_0000;

    /// <summary>
    /// Result for input whose bytes are not a supported PE. Carries the root
    /// identity and an <see cref="AnalysisStatus.UnsupportedOrInvalidRootFormat"/>
    /// status with no observations — never a favorable disposition.
    /// </summary>
    public static ScanResult Unsupported(string sha256, long size)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentOutOfRangeException.ThrowIfNegative(size);
        var root = new ArtifactNode(
            RootArtifactId, string.Empty, sha256, size,
            ArtifactCompleteness.Unsupported, ImmutableArray<string>.Empty);
        return new ScanResult(
            string.Empty, AnalysisStatus.UnsupportedOrInvalidRootFormat,
            ArtifactCompleteness.Unsupported, ImmutableArray.Create(root),
            ImmutableArray<Observation>.Empty, ImmutableArray<CapabilityFinding>.Empty,
            ImmutableArray<string>.Empty);
    }

    /// <summary>
    /// Result for input that begins as a PE but fails structural parsing. Incomplete
    /// with a <see cref="ArtifactCompleteness.Malformed"/> root — a parser rejection is
    /// never treated as evidence that a capability is absent.
    /// </summary>
    public static ScanResult Malformed(string sha256, long size)
    {
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentOutOfRangeException.ThrowIfNegative(size);
        var root = new ArtifactNode(
            RootArtifactId, string.Empty, sha256, size,
            ArtifactCompleteness.Malformed, ImmutableArray<string>.Empty);
        return new ScanResult(
            string.Empty, AnalysisStatus.Incomplete, ArtifactCompleteness.Malformed,
            ImmutableArray.Create(root), ImmutableArray<Observation>.Empty,
            ImmutableArray<CapabilityFinding>.Empty, ImmutableArray<string>.Empty);
    }

    public static ScanResult Map(PeAnalysisResult analysis, string sha256, long size)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentOutOfRangeException.ThrowIfNegative(size);

        var layout = analysis.Layout;
        var clr = analysis.Clr;
        var trust = analysis.Trust;
        var rich = analysis.RichSummary;

        var observations = ImmutableArray.CreateBuilder<Observation>();
        var sequence = 0;
        void Add(string kind, string description, ParserConfidence confidence, long? offset = null)
        {
            var id = "pe-obs-" + (++sequence).ToString("D4", CultureInfo.InvariantCulture);
            observations.Add(new Observation(
                id, kind, CleanText(description), confidence,
                new SourceLocation(RootArtifactId, offset, null)));
        }

        Add("pe.image",
            $"{(layout.IsPe32Plus ? "PE32+" : "PE32")} image, machine {MachineName(layout.Machine)} " +
            $"(0x{layout.Machine:x4}).",
            ParserConfidence.High);

        foreach (var section in layout.Sections)
        {
            Add("pe.section",
                $"Section '{section.Name}' [{Permissions(section.Characteristics)}] " +
                $"raw {section.RawSize} bytes @ 0x{section.RawOffset:x}, " +
                $"virtual {section.VirtualSize} bytes @ 0x{section.VirtualAddress:x}.",
                ParserConfidence.High, section.RawOffset);
        }

        if (layout.EntryPointRva == 0)
        {
            Add("pe.entry-point", "No entry point (RVA 0); typical of resource-only libraries.",
                ParserConfidence.High);
        }
        else
        {
            var host = ContainingSection(layout, layout.EntryPointRva);
            var description = host is null
                ? $"Entry point RVA 0x{layout.EntryPointRva:x} is not mapped by any section."
                : $"Entry point RVA 0x{layout.EntryPointRva:x} maps into section '{host.Name}' " +
                  $"({((host.Characteristics & MemExecute) != 0 ? "executable" : "non-executable")}).";
            Add("pe.entry-point", description, ParserConfidence.High);
        }

        foreach (var anomaly in layout.StructuralAnomalies)
            Add("pe.anomaly", anomaly, ParserConfidence.High);

        if (layout.OverlayLength > 0)
            Add("pe.overlay",
                $"Overlay of {layout.OverlayLength} bytes past the mapped image at offset 0x{layout.OverlayOffset:x}.",
                ParserConfidence.High, layout.OverlayOffset);

        if (layout.CertificateOffset is { } certOffset)
            Add("pe.certificate",
                $"Certificate table of {layout.CertificateLength} bytes at file offset 0x{certOffset:x}.",
                ParserConfidence.High, certOffset);

        Add("pe.trust",
            $"Authenticode disposition {trust.Disposition}; native status 0x{trust.NativeStatus:x8}; " +
            $"{trust.SignatureCount} signature record(s)" +
            (trust.RevocationIndeterminate ? "; revocation indeterminate (offline)." : "."),
            ParserConfidence.High);

        Add("pe.clr",
            clr.IsManaged
                ? $"Managed assembly '{clr.AssemblyName ?? "<unnamed>"}'; {clr.AssemblyReferences.Length} assembly " +
                  $"reference(s), {clr.Methods.Length} method(s), {clr.UnresolvedEdges.Length} unresolved edge(s)" +
                  (clr.TruncatedByPolicy ? "; metadata walk truncated by policy." : ".")
                : "No CLR metadata; native image.",
            clr.IsManaged ? ParserConfidence.Medium : ParserConfidence.High);

        Add("pe.rich-parser",
            $"AsmResolver agreement: {analysis.RichParserAgreed}; {rich.ImportModuleCount} import module(s), " +
            $"{rich.ImportedSymbolCount} imported symbol(s), {rich.ExportCount} export(s); " +
            $"resources {(rich.HasResources ? "present" : "absent")}; " +
            $"TLS directory {(rich.HasTlsDirectory ? "present" : "absent")}.",
            ParserConfidence.Medium);

        // Capability rules can only cite imports whose names are readable, so an image
        // that exposes none has either had its import table stripped (everything resolved
        // at run time) or imports purely by ordinal. Either way the enabled checks cannot
        // see what it calls, and that absence of evidence must never read as a favourable
        // result: forcing Incomplete makes the verdict engine withhold a disposition
        // rather than report the most favourable one available.
        //
        // Only judged when the rich parse produced a usable inventory. If it did not, a
        // limitation already carries the incompleteness, and a visibility claim here
        // would be describing an inventory that was never collected.
        var importVisibilityUnknown = false;
        if (analysis.Limitations.IsDefaultOrEmpty && !clr.IsManaged && layout.EntryPointRva != 0)
        {
            var readable = 0;
            var unreadable = 0;
            foreach (var import in rich.Imports)
            {
                // "module!Api" is readable; "module!#42" is an ordinal, and anything
                // without a symbol is unusable to a rule just the same.
                var bang = import.LastIndexOf('!');
                if (bang < 0 || bang == import.Length - 1 || import[bang + 1] == '#') unreadable++;
                else readable++;
            }

            if (readable == 0)
            {
                importVisibilityUnknown = true;
                Add("pe.import-visibility",
                    unreadable == 0
                        ? "The import table is empty or absent, so no imported API names were available to " +
                          "match. This is expected of a packed image that resolves its imports at run time."
                        : $"All {unreadable} imported symbol(s) are ordinal-only, so no API names were " +
                          "available to match.",
                    ParserConfidence.High);
            }
            else if (unreadable >= readable)
            {
                importVisibilityUnknown = true;
                Add("pe.import-visibility",
                    $"{unreadable} of {readable + unreadable} imported symbol(s) are ordinal-only, so a " +
                    "matchable API may not be visible to the enabled checks.",
                    ParserConfidence.High);
            }
        }

        // Per-API evidence observations that capability rules cite. Bounded so a
        // pathological import table cannot flood the result; hitting the cap drops a
        // potentially matchable API, which is a completeness event.
        const int maxEvidenceObservations = 4096;
        var evidenceEmitted = 0;
        var evidenceTruncated = false;
        void AddEvidence(string kind, string description)
        {
            if (evidenceEmitted >= maxEvidenceObservations)
            {
                evidenceTruncated = true;
                return;
            }
            evidenceEmitted++;
            Add(kind, description, ParserConfidence.High);
        }

        foreach (var import in rich.Imports)
            AddEvidence("pe.import", import);
        foreach (var reference in clr.ExternalReferences)
        {
            if (reference.SourceKind != "P/Invoke implementation") continue;
            AddEvidence("pe.pinvoke", reference.DirectlyCalledByApplication
                ? reference.DisplayName + " (app-called)"
                : reference.DisplayName);
        }

        var incomplete =
            !analysis.Limitations.IsDefaultOrEmpty
            || !analysis.RichParserAgreed
            || clr.TruncatedByPolicy
            || evidenceTruncated
            || importVisibilityUnknown
            || trust.Disposition is TrustDisposition.IndeterminateOffline
                or TrustDisposition.PlatformUnavailable
                or TrustDisposition.Malformed;

        var status = incomplete ? AnalysisStatus.Incomplete : AnalysisStatus.Complete;
        var completeness = incomplete ? ArtifactCompleteness.TruncatedByPolicy : ArtifactCompleteness.Complete;

        var countervailing = trust.Disposition == TrustDisposition.Trusted
            ? ImmutableArray.Create("Windows platform trust verified the embedded signature.")
            : ImmutableArray<string>.Empty;

        var root = new ArtifactNode(
            RootArtifactId, string.Empty, sha256, size, completeness,
            ImmutableArray<string>.Empty, ApplicationLinkage.Unknown);

        return new ScanResult(
            string.Empty, status, completeness, ImmutableArray.Create(root),
            observations.ToImmutable(), ImmutableArray<CapabilityFinding>.Empty, countervailing);
    }

    private static string MachineName(ushort machine) => machine switch
    {
        0x8664 => "x64",
        0x014c => "x86",
        0xAA64 => "ARM64",
        0x01c0 or 0x01c4 => "ARM",
        0x0200 => "Itanium",
        0x5064 => "RISC-V64",
        _ => "unknown",
    };

    private static PeSection? ContainingSection(PeLayout layout, uint rva)
    {
        foreach (var section in layout.Sections)
        {
            var span = Math.Max(section.VirtualSize, section.RawSize);
            if (rva >= section.VirtualAddress && (ulong)rva < (ulong)section.VirtualAddress + span)
                return section;
        }
        return null;
    }

    private static string Permissions(uint characteristics)
    {
        Span<char> flags =
        [
            (characteristics & MemRead) != 0 ? 'R' : '-',
            (characteristics & MemWrite) != 0 ? 'W' : '-',
            (characteristics & MemExecute) != 0 ? 'X' : '-',
        ];
        return new string(flags);
    }

    // Section names and reader-generated anomaly text are sample-influenced and may
    // carry control characters. Replace them so observation text stays printable,
    // and bound the length below the contract ceiling.
    private static string CleanText(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var character in text)
            builder.Append(IsUnsafe(character) ? '.' : character);

        var cleaned = builder.ToString();
        if (cleaned.Length <= ContractLimits.MaxStringLength)
            return cleaned;

        // Never truncate through a surrogate pair; the contract validator rejects a
        // lone surrogate as malformed Unicode.
        var end = ContractLimits.MaxStringLength;
        if (char.IsHighSurrogate(cleaned[end - 1])) end--;
        return cleaned[..end];
    }

    private static bool IsUnsafe(char character)
    {
        var code = (int)character;
        // C0/C1 control characters and DEL, plus the bidirectional format controls the
        // contract validator rejects (U+202A..U+202E, U+2066..U+2069). Neutralising them
        // here guarantees observation text built from hostile metadata (e.g. a managed
        // assembly name, which unlike an ASCII section name can carry arbitrary Unicode)
        // still validates, instead of throwing at serialisation time and crashing the worker.
        return code < 0x20
            || (code >= 0x7F && code <= 0x9F)
            || (code >= 0x202A && code <= 0x202E)
            || (code >= 0x2066 && code <= 0x2069);
    }
}
