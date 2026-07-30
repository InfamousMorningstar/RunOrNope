namespace RunOrNope.Analyzers.Msi;

/// <summary>Fixed ceilings for metadata read from an untrusted installer database.</summary>
public sealed record MsiAnalysisLimits
{
    public int MaxTables { get; init; } = 256;
    public int MaxRowsPerTable { get; init; } = 8_192;
    public int MaxTotalRows { get; init; } = 32_768;
    public int MaxFieldsPerRecord { get; init; } = 32;
    public int MaxTextScalars { get; init; } = 12_288;
    public int MaxDirectoryDepth { get; init; } = 256;
    public static MsiAnalysisLimits Default { get; } = new();

    public void Validate()
    {
        if (MaxTables <= 0) throw new ArgumentOutOfRangeException(nameof(MaxTables));
        if (MaxRowsPerTable <= 0) throw new ArgumentOutOfRangeException(nameof(MaxRowsPerTable));
        if (MaxTotalRows <= 0) throw new ArgumentOutOfRangeException(nameof(MaxTotalRows));
        if (MaxFieldsPerRecord <= 0) throw new ArgumentOutOfRangeException(nameof(MaxFieldsPerRecord));
        if (MaxTextScalars <= 0) throw new ArgumentOutOfRangeException(nameof(MaxTextScalars));
        if (MaxDirectoryDepth <= 0) throw new ArgumentOutOfRangeException(nameof(MaxDirectoryDepth));
    }
}
