using System.Collections.Immutable;
using RunOrNope.Analyzers.Content;
using RunOrNope.Contracts;

namespace RunOrNope.Analyzers.Msi;

public sealed record MsiRootInput(
    string DatabasePath,
    string Sha256,
    long Size);

public interface IMsiAnalyzer
{
    ScanResult Analyze(
        MsiRootInput input,
        IMsiMaterializationService materialization,
        ExtractionBudget? extractionBudget,
        CancellationToken cancellationToken);
}

/// <summary>
/// Coordinates fixed-catalog, read-only MSI inventory and maps its unnumbered facts and
/// lazy streams into the shared artifact graph. It never executes installer behavior.
/// </summary>
public sealed class MsiAnalyzer : IMsiAnalyzer
{
    private readonly MsiAnalysisLimits limits;
    private readonly IMsiDatabaseFactory databaseFactory;

    public MsiAnalyzer(MsiAnalysisLimits? limits = null)
        : this(limits ?? MsiAnalysisLimits.Default, new MsiDatabaseFactory())
    {
    }

    internal MsiAnalyzer(
        MsiAnalysisLimits limits,
        IMsiDatabaseFactory databaseFactory)
    {
        this.limits = limits ?? throw new ArgumentNullException(nameof(limits));
        this.databaseFactory = databaseFactory
            ?? throw new ArgumentNullException(nameof(databaseFactory));
        limits.Validate();
    }

    public ScanResult Analyze(
        MsiRootInput input,
        IMsiMaterializationService materialization,
        ExtractionBudget? extractionBudget,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentException.ThrowIfNullOrWhiteSpace(input.DatabasePath);
        ArgumentNullException.ThrowIfNull(input.Sha256);
        ArgumentNullException.ThrowIfNull(materialization);
        ArgumentOutOfRangeException.ThrowIfNegative(input.Size);
        cancellationToken.ThrowIfCancellationRequested();

        var inventory = new MsiPackageInventory(limits);
        IMsiDatabaseReader database;
        try
        {
            database = databaseFactory.OpenReadOnly(input.DatabasePath);
        }
        catch (IOException exception)
        {
            inventory.MarkIncomplete(
                $"MSI database inventory could not be opened read-only: {exception.Message}",
                ArtifactCompleteness.Unavailable);
            return BuildResult(input, inventory.Finish(), extractionBudget);
        }
        catch (UnauthorizedAccessException exception)
        {
            inventory.MarkIncomplete(
                $"MSI database inventory was unavailable: {exception.Message}",
                ArtifactCompleteness.Unavailable);
            return BuildResult(input, inventory.Finish(), extractionBudget);
        }
        catch (OverflowException exception)
        {
            inventory.MarkIncomplete(
                $"MSI database inventory could not be represented safely: {exception.Message}",
                ArtifactCompleteness.Malformed);
            return BuildResult(input, inventory.Finish(), extractionBudget);
        }

        using (database)
        {
            ReadSummary(database, inventory, cancellationToken);
            var tables = EnumerateTables(database, inventory, cancellationToken);
            inventory.AddTableCountMetric(tables.Length);

            var examined = new HashSet<string>(StringComparer.Ordinal);
            foreach (var tableName in tables.Take(limits.MaxTables))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var displayName = MsiTextPolicy.Sanitize(
                    tableName,
                    limits.MaxTextScalars).DisplayText;
                var definition = MsiTables.FindPackage(tableName);
                if (definition is null)
                {
                    inventory.AddUnsupportedTable(displayName);
                    continue;
                }
                if (!examined.Add(definition.Name)) continue;

                try
                {
                    var rows = database.Query(
                        definition,
                        [],
                        limits,
                        cancellationToken);
                    inventory.ConsumeTable(
                        definition,
                        rows,
                        database,
                        cancellationToken);
                    // The aggregate ceiling stops the whole inventory. Continuing would
                    // re-read and re-report the same exhaustion for every remaining table.
                    if (inventory.AggregateRowsExhausted) break;
                }
                catch (IOException exception)
                {
                    inventory.MarkIncomplete(
                        $"Present MSI table {definition.Name} was unreadable: {exception.Message}",
                        exception is MsiDataIncompleteException
                            ? ArtifactCompleteness.TruncatedByPolicy
                            : ArtifactCompleteness.Unavailable);
                }
                catch (OverflowException exception)
                {
                    inventory.MarkIncomplete(
                        $"Present MSI table {definition.Name} could not be represented safely: {exception.Message}",
                        ArtifactCompleteness.Malformed);
                }
            }

            var package = inventory.Finish();
            // ArtifactGraphBuilder eagerly consumes every lazy root entry before this
            // using scope closes the database and its read-only native handle.
            return BuildResult(input, package, extractionBudget);
        }
    }

    private ImmutableArray<string> EnumerateTables(
        IMsiDatabaseReader database,
        MsiPackageInventory inventory,
        CancellationToken cancellationToken)
    {
        try
        {
            var tables = database.EnumerateTables(limits, cancellationToken);
            if (tables.IsDefault)
            {
                inventory.MarkIncomplete(
                    "MSI table inventory returned an uninitialized result.",
                    ArtifactCompleteness.Malformed);
                return [];
            }
            if (tables.Length > limits.MaxTables)
            {
                inventory.MarkIncomplete(
                    "MSI table inventory exceeded the configured table limit.",
                    ArtifactCompleteness.TruncatedByPolicy);
            }
            return tables;
        }
        catch (IOException exception)
        {
            inventory.MarkIncomplete(
                $"MSI table inventory was unreadable: {exception.Message}",
                exception is MsiDataIncompleteException
                    ? ArtifactCompleteness.TruncatedByPolicy
                    : ArtifactCompleteness.Unavailable);
            return [];
        }
        catch (OverflowException exception)
        {
            inventory.MarkIncomplete(
                $"MSI table inventory could not be represented safely: {exception.Message}",
                ArtifactCompleteness.Malformed);
            return [];
        }
    }

    private void ReadSummary(
        IMsiDatabaseReader database,
        MsiPackageInventory inventory,
        CancellationToken cancellationToken)
    {
        try
        {
            var summary = database.ReadSummary(limits, cancellationToken);
            if (summary.IsDefault)
            {
                inventory.MarkIncomplete(
                    "MSI SummaryInformation returned an uninitialized result.",
                    ArtifactCompleteness.Malformed);
                return;
            }
            inventory.AddSummaryFacts(summary);
        }
        catch (IOException exception)
        {
            inventory.MarkIncomplete(
                $"MSI SummaryInformation was unreadable: {exception.Message}",
                ArtifactCompleteness.Unavailable);
        }
        catch (OverflowException exception)
        {
            inventory.MarkIncomplete(
                $"MSI SummaryInformation could not be represented safely: {exception.Message}",
                ArtifactCompleteness.Malformed);
        }
    }

    private static ScanResult BuildResult(
        MsiRootInput input,
        MsiPackageInventoryResult package,
        ExtractionBudget? extractionBudget)
    {
        var root = new ArtifactNode(
            ScanArtifacts.RootId,
            string.Empty,
            input.Sha256,
            input.Size,
            package.Completeness,
            ImmutableArray<string>.Empty);
        var graph = ArtifactGraphBuilder.Build(
            new RootContainerInput(root, package.Entries, package.Facts),
            LeafContainerProvider.Instance,
            extractionBudget);
        var complete = package.IsComplete && !graph.Incomplete;
        return new ScanResult(
            string.Empty,
            complete ? AnalysisStatus.Complete : AnalysisStatus.Incomplete,
            graph.Artifacts[0].Completeness,
            graph.Artifacts,
            graph.Observations,
            ImmutableArray<CapabilityFinding>.Empty,
            ImmutableArray<string>.Empty);
    }

    private sealed class LeafContainerProvider : IContainerProvider
    {
        internal static LeafContainerProvider Instance { get; } = new();

        public ContainerReadResult Read(ReadOnlyMemory<byte> content) =>
            ContainerReadResult.NotRecognized;
    }
}
