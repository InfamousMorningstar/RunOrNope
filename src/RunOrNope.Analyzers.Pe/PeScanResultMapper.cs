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
    private const string RootArtifactId = "root";
    private const uint MemExecute = 0x2000_0000;
    private const uint MemRead = 0x4000_0000;
    private const uint MemWrite = 0x8000_0000;

    public static ScanResult Map(PeAnalysisResult analysis, string sha256, long size, bool isSupportedPe)
    {
        ArgumentNullException.ThrowIfNull(analysis);
        ArgumentNullException.ThrowIfNull(sha256);
        ArgumentOutOfRangeException.ThrowIfNegative(size);

        if (!isSupportedPe)
        {
            var unsupportedRoot = new ArtifactNode(
                RootArtifactId, string.Empty, sha256, size,
                ArtifactCompleteness.Unsupported, ImmutableArray<string>.Empty);
            return new ScanResult(
                string.Empty, AnalysisStatus.UnsupportedOrInvalidRootFormat,
                ArtifactCompleteness.Unsupported, ImmutableArray.Create(unsupportedRoot),
                ImmutableArray<Observation>.Empty, ImmutableArray<CapabilityFinding>.Empty,
                ImmutableArray<string>.Empty);
        }

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

        var incomplete =
            !analysis.Limitations.IsDefaultOrEmpty
            || !analysis.RichParserAgreed
            || clr.TruncatedByPolicy
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
        {
            var code = (int)character;
            var isControl = code < 0x20 || (code >= 0x7F && code <= 0x9F);
            builder.Append(isControl ? '.' : character);
        }

        var cleaned = builder.ToString();
        return cleaned.Length <= ContractLimits.MaxStringLength
            ? cleaned
            : cleaned[..ContractLimits.MaxStringLength];
    }
}
