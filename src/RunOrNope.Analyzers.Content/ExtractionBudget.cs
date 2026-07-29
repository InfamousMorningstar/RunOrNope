using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.Analyzers.Content;

/// <summary>Names the ceiling that stopped a walk, so a report can say which one.</summary>
public enum BudgetLimit
{
    Depth,
    Artifacts,
    TotalExpandedBytes,
    ArtifactBytes,
    EntriesPerContainer,
    ExpansionRatio,
}

/// <summary>
/// Immutable hard ceilings for a recursive walk. Every value is a stop, not a target:
/// reaching one truncates the analysis rather than failing it.
/// </summary>
public sealed record ExtractionCeilings
{
    public int MaxDepth { get; init; } = 8;

    /// <summary>
    /// Below <see cref="ContractLimits.MaxArtifacts"/> on purpose, so a graph built at
    /// the ceiling still leaves room for the MSI analyzer's own nodes and validates.
    /// </summary>
    public int MaxArtifacts { get; init; } = 2048;

    public long MaxTotalExpandedBytes { get; init; } = 1L << 30;
    public long MaxArtifactBytes { get; init; } = 256L << 20;
    public int MaxEntriesPerContainer { get; init; } = 16_384;
    public int MaxExpansionRatio { get; init; } = 200;

    public static ExtractionCeilings Default { get; } = new();
}

/// <summary>
/// Streamed accounting for a recursive walk. Charges are made against bytes actually
/// read rather than the sizes a container declares, and no method throws — exhaustion
/// is reported through <see cref="Stops"/> so the caller degrades to
/// <see cref="ArtifactCompleteness.TruncatedByPolicy"/>.
/// </summary>
public sealed class ExtractionBudget(ExtractionCeilings? ceilings = null)
{
    private readonly HashSet<BudgetLimit> stops = [];
    private readonly List<BudgetLimit> stopOrder = [];

    public ExtractionCeilings Ceilings { get; } = ceilings ?? ExtractionCeilings.Default;

    /// <summary>Entries seen, counted before identity deduplication (see <see cref="ChargeEntry"/>).</summary>
    public long EntriesCharged { get; private set; }

    public long TotalExpandedBytes { get; private set; }

    public int ArtifactCount { get; private set; }

    /// <summary>Ceilings hit, in the order they were first hit.</summary>
    public ImmutableArray<BudgetLimit> Stops => [.. stopOrder];

    public bool Exhausted => stopOrder.Count > 0;

    public bool AllowsDepth(int depth)
    {
        if (depth <= Ceilings.MaxDepth) return true;
        Stop(BudgetLimit.Depth);
        return false;
    }

    /// <summary>
    /// Charges one logical entry. Called for every entry a container declares, including
    /// entries whose content deduplicates to an existing node: deduplication is an
    /// analysis optimisation, and charging only unique content would let a container
    /// repeat one payload for unlimited free expansion.
    /// </summary>
    public bool ChargeEntry(int entryIndexInContainer)
    {
        EntriesCharged++;
        if (entryIndexInContainer >= Ceilings.MaxEntriesPerContainer)
        {
            Stop(BudgetLimit.EntriesPerContainer);
            return false;
        }
        return true;
    }

    public bool ChargeArtifact()
    {
        if (ArtifactCount >= Ceilings.MaxArtifacts)
        {
            Stop(BudgetLimit.Artifacts);
            return false;
        }
        ArtifactCount++;
        return true;
    }

    /// <summary>
    /// Charges bytes as they are read. <paramref name="artifactBytesSoFar"/> is the
    /// running total for the entry being read, so one entry cannot consume the whole
    /// budget and a hugely compressible entry trips the ratio tripwire.
    /// </summary>
    public bool ChargeBytes(long bytes, long artifactBytesSoFar, long compressedSize)
    {
        if (bytes <= 0) return !Exhausted;

        TotalExpandedBytes += bytes;

        var allowed = true;
        if (TotalExpandedBytes > Ceilings.MaxTotalExpandedBytes)
        {
            Stop(BudgetLimit.TotalExpandedBytes);
            allowed = false;
        }
        if (artifactBytesSoFar > Ceilings.MaxArtifactBytes)
        {
            Stop(BudgetLimit.ArtifactBytes);
            allowed = false;
        }
        // A compressed size of zero tells us nothing, so it is not a ratio claim.
        if (compressedSize > 0 && artifactBytesSoFar / compressedSize > Ceilings.MaxExpansionRatio)
        {
            Stop(BudgetLimit.ExpansionRatio);
            allowed = false;
        }
        return allowed;
    }

    private void Stop(BudgetLimit limit)
    {
        if (stops.Add(limit)) stopOrder.Add(limit);
    }

    public static string Describe(BudgetLimit limit) => limit switch
    {
        BudgetLimit.Depth => "nesting depth",
        BudgetLimit.Artifacts => "artifact count",
        BudgetLimit.TotalExpandedBytes => "total expanded bytes",
        BudgetLimit.ArtifactBytes => "single-artifact size",
        BudgetLimit.EntriesPerContainer => "entries in one container",
        BudgetLimit.ExpansionRatio => "expansion ratio",
        _ => "an extraction ceiling",
    };
}
