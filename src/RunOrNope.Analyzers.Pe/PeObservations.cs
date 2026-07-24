using System.Collections.Immutable;

namespace RunOrNope.Analyzers.Pe;

public sealed record PeSection(
    string Name,
    uint VirtualAddress,
    uint VirtualSize,
    uint RawOffset,
    uint RawSize,
    uint Characteristics);

public sealed record PeLayout(
    bool IsPe32Plus,
    ushort Machine,
    uint EntryPointRva,
    uint SizeOfHeaders,
    ImmutableArray<PeSection> Sections,
    long? CertificateOffset,
    long CertificateLength,
    long OverlayOffset,
    long OverlayLength,
    ImmutableArray<string> StructuralAnomalies)
{
    public long? RvaToFileOffset(uint rva)
    {
        if (rva < SizeOfHeaders) return rva;
        foreach (var section in Sections)
        {
            var span = Math.Max(section.VirtualSize, section.RawSize);
            if (rva >= section.VirtualAddress && (ulong)rva < (ulong)section.VirtualAddress + span)
            {
                var delta = rva - section.VirtualAddress;
                return delta < section.RawSize ? checked((long)section.RawOffset + delta) : null;
            }
        }
        return null;
    }
}

public sealed class PeFormatException : IOException
{
    public PeFormatException(string message) : base(message) { }
    public PeFormatException(string message, Exception innerException) : base(message, innerException) { }
}

public enum TrustDisposition { Trusted, Untrusted, NoSignature, Malformed, IndeterminateOffline, PlatformUnavailable }

public sealed record AuthenticodePolicy(
    bool CacheOnly = true,
    bool NetworkRetrievalDisabled = true,
    bool NonInteractive = true,
    bool StrictPadding = true,
    bool EnumerateAllSignatures = true);

public sealed record AuthenticodeResult(
    int NativeStatus,
    TrustDisposition Disposition,
    bool RevocationIndeterminate,
    DateTimeOffset? Timestamp,
    string? CatalogContext,
    int SignatureCount = 0);

public sealed record ClrMethodObservation(
    int MetadataToken,
    string DeclaringType,
    string Name,
    int IlSize,
    ImmutableArray<int> DirectCallTokens);

public sealed record ClrExternalReference(
    int MetadataToken,
    string DisplayName,
    string SourceKind,
    bool DirectlyCalledByApplication);

public sealed record ClrAnalysisResult(
    bool IsManaged,
    string? AssemblyName,
    ImmutableArray<string> AssemblyReferences,
    ImmutableArray<ClrMethodObservation> Methods,
    ImmutableArray<ClrExternalReference> ExternalReferences,
    bool TruncatedByPolicy,
    ImmutableArray<string> UnresolvedEdges);

public sealed record ClrAnalysisLimits(int MaxMethods = 50_000, int MaxInstructionsPerMethod = 100_000);

public sealed record PeAnalysisResult(
    PeLayout Layout,
    ClrAnalysisResult Clr,
    AuthenticodeResult Trust,
    RichPeSummary RichSummary,
    bool RichParserAgreed,
    ImmutableArray<string> Limitations);

public sealed record RichPeSummary(
    int ImportModuleCount,
    int ImportedSymbolCount,
    int ExportCount,
    int DebugEntryCount,
    bool HasResources,
    bool HasTlsDirectory,
    ImmutableArray<string> Imports,
    ImmutableArray<string> Exports);

public sealed record ArtifactInput(string ArtifactId, Stream Content, long Length);
public sealed record AnalysisContext(int MaximumRichParserBytes = 256 * 1024 * 1024);

public interface IArtifactAnalyzer
{
    ValueTask<PeAnalysisResult> AnalyzeAsync(
        ArtifactInput input,
        AnalysisContext context,
        CancellationToken cancellationToken);
}
