namespace RunOrNope.Analyzers.Msi;

public enum MsiFormatDisposition
{
    MsiPackage,
    OtherCompoundFile,
    Malformed,
}

public sealed record MsiPreflightResult(
    MsiFormatDisposition Disposition,
    string? IncompleteReason);

public sealed record MsiTextResult(
    string DisplayText,
    bool WasNeutralized,
    bool WasTruncated,
    int OriginalScalars);

public sealed record MsiDirectoryRow(
    string Key,
    string? ParentKey,
    string DefaultDirectory);

public enum MsiDirectoryStatus
{
    Complete,
    SelfParent,
    Cycle,
    Orphan,
    DepthExceeded,
    LengthExceeded,
}

public sealed record MsiDirectoryResolution(
    string DisplayPath,
    MsiDirectoryStatus Status);

public interface IMsiMaterializedFile : IDisposable
{
    string Path { get; }
}

public interface IMsiMaterializationService
{
    IMsiMaterializedFile Materialize(
        ReadOnlyMemory<byte> content,
        CancellationToken cancellationToken);
}
