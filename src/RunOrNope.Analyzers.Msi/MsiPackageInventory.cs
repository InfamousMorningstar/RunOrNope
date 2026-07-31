using System.Collections.Immutable;
using System.Globalization;
using RunOrNope.Analyzers.Content;
using RunOrNope.Contracts;

namespace RunOrNope.Analyzers.Msi;

internal sealed record MsiPackageInventoryResult(
    ImmutableArray<ArtifactObservationFact> Facts,
    ImmutableArray<ContainerEntry> Entries,
    bool IsComplete,
    ArtifactCompleteness Completeness);

/// <summary>
/// Converts bounded rows from the fixed MSI catalog into display evidence and lazy
/// content entries. Raw identities are retained only for exact in-memory relationship
/// and stream matching; they never become SQL, paths, commands, or native inputs.
/// </summary>
internal sealed class MsiPackageInventory
{
    private readonly MsiAnalysisLimits limits;
    private readonly ImmutableArray<ArtifactObservationFact>.Builder facts =
        ImmutableArray.CreateBuilder<ArtifactObservationFact>();
    private readonly ImmutableArray<ContainerEntry>.Builder entries =
        ImmutableArray.CreateBuilder<ContainerEntry>();
    private readonly Dictionary<string, MsiDirectoryRow> directories =
        new(StringComparer.Ordinal);
    private readonly List<(string RawName, string DisplayName)> embeddedCabinets = [];
    private readonly Dictionary<string, StreamReference> streams =
        new(StringComparer.Ordinal);
    private int totalRows;
    private bool complete = true;
    private bool aggregateRowsExhausted;
    private ArtifactCompleteness completeness = ArtifactCompleteness.Complete;

    /// <summary>
    /// True once the aggregate row ceiling has been reached. Enumeration stops rather than
    /// re-reporting the same exhaustion for every remaining table in the catalog.
    /// </summary>
    internal bool AggregateRowsExhausted => aggregateRowsExhausted;

    internal MsiPackageInventory(MsiAnalysisLimits limits)
    {
        this.limits = limits ?? throw new ArgumentNullException(nameof(limits));
        limits.Validate();
    }

    internal void AddTableCountMetric(int tableCount) =>
        AddFact(
            "msi.inventory-metrics",
            $"Inventory metrics: tables observed {tableCount}.",
            ParserConfidence.High);

    internal void AddUnsupportedTable(string displayName)
    {
        AddFact(
            "msi.table-unsupported",
            $"Present MSI table '{displayName}' is not in the fixed supported catalog; its semantics were not examined.",
            ParserConfidence.High);
        MarkIncomplete(
            "A present MSI table was unsupported, so the database inventory is incomplete.",
            ArtifactCompleteness.Unsupported);
    }

    internal void ConsumeTable(
        MsiTableDefinition definition,
        IEnumerable<MsiRow> rows,
        IMsiDatabaseReader database,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(rows);
        ArgumentNullException.ThrowIfNull(database);

        var rowCount = 0;
        var maxScalars = new int[definition.Columns.Length];
        try
        {
            foreach (var row in rows)
            {
                cancellationToken.ThrowIfCancellationRequested();
                rowCount++;
                if (rowCount > limits.MaxRowsPerTable)
                {
                    MarkIncomplete(
                        $"MSI table {definition.Name} exceeded the configured row limit.",
                        ArtifactCompleteness.TruncatedByPolicy);
                    break;
                }

                totalRows++;
                if (totalRows > limits.MaxTotalRows)
                {
                    aggregateRowsExhausted = true;
                    MarkIncomplete(
                        "MSI database inventory exceeded the configured total row limit.",
                        ArtifactCompleteness.TruncatedByPolicy);
                    break;
                }

                if (row.Fields.IsDefault || row.Fields.Length > limits.MaxFieldsPerRecord)
                {
                    MarkIncomplete(
                        $"MSI table {definition.Name} returned a record beyond the configured field limit.",
                        ArtifactCompleteness.TruncatedByPolicy);
                    break;
                }

                if (row.Fields.Length < definition.Columns.Length)
                {
                    MarkIncomplete(
                        $"MSI table {definition.Name} returned fewer fields than its fixed schema.",
                        ArtifactCompleteness.Malformed);
                    continue;
                }

                RecordMetricScalars(row, maxScalars);
                if (!ValidateRow(definition, row)) continue;
                MapRow(definition, row, database);
            }
        }
        catch (IOException exception)
        {
            MarkIncomplete(
                $"Present MSI table {definition.Name} was unreadable: {exception.Message}",
                exception is MsiDataIncompleteException
                    ? ArtifactCompleteness.TruncatedByPolicy
                    : ArtifactCompleteness.Unavailable);
        }
        catch (OverflowException exception)
        {
            MarkIncomplete(
                $"Present MSI table {definition.Name} could not be represented safely: {exception.Message}",
                ArtifactCompleteness.Malformed);
        }

        var scalarMetrics = definition.Columns
            .Select((column, index) => (column, index))
            .Where(item => item.column.Type == MsiColumnType.String)
            .Select(item =>
                $"{definition.Name}.{item.column.Name}={maxScalars[item.index].ToString(CultureInfo.InvariantCulture)}")
            .ToArray();
        AddFact(
            "msi.inventory-metrics",
            $"Inventory metrics: table {definition.Name}; rows {Math.Min(rowCount, limits.MaxRowsPerTable).ToString(CultureInfo.InvariantCulture)}; " +
            $"maximum scalar lengths {(
                scalarMetrics.Length == 0 ? "none" : string.Join(", ", scalarMetrics))}.",
            ParserConfidence.High);
    }

    internal MsiPackageInventoryResult Finish()
    {
        ResolveDirectories();
        CorrelateEmbeddedCabinets();
        return new MsiPackageInventoryResult(
            facts.ToImmutable(),
            entries.ToImmutable(),
            complete,
            completeness);
    }

    internal void MarkIncomplete(string reason, ArtifactCompleteness incoming)
    {
        complete = false;
        completeness = MoreIncomplete(completeness, incoming);
        var bounded = MsiTextPolicy.Sanitize(reason, ContractLimits.MaxStringLength);
        facts.Add(new ArtifactObservationFact(
            "msi.incomplete",
            bounded.DisplayText,
            ParserConfidence.High));
    }

    internal void AddSummaryFacts(ImmutableArray<MsiSummaryProperty> summary)
    {
        foreach (var property in summary)
        {
            if (!property.IsComplete || !property.Value.IsComplete)
            {
                MarkIncomplete(
                    property.IncompleteReason
                        ?? property.Value.IncompleteReason
                        ?? $"Summary property {property.PropertyId} was unreadable.",
                    ArtifactCompleteness.Malformed);
                continue;
            }

            switch (property.PropertyId)
            {
                case 1:
                    AddSummaryInteger("Code Page", property.Value);
                    break;
                case 2:
                    AddSummaryText("Title", property.Value);
                    break;
                case 3:
                    AddSummaryText("Subject", property.Value);
                    break;
                case 4:
                    AddSummaryText("Author", property.Value);
                    break;
                case 5:
                    AddSummaryText("Keywords", property.Value);
                    break;
                case 6:
                    AddSummaryText("Comments", property.Value);
                    break;
                case 7:
                    AddSummaryText("Template", property.Value);
                    break;
                case 8:
                    AddSummaryText("Last Saved By", property.Value);
                    break;
                case 9:
                    AddSummaryText("Revision Number", property.Value);
                    break;
                case 10:
                    AddSummaryDuration(property.Value);
                    break;
                case 11:
                    AddSummaryTimestamp("Last Printed", property.Value);
                    break;
                case 12:
                    AddSummaryTimestamp("Created", property.Value);
                    break;
                case 13:
                    AddSummaryTimestamp("Last Saved", property.Value);
                    break;
                case 14:
                    AddSummaryInteger("Page Count", property.Value);
                    break;
                case 15:
                    AddWordCount(property.Value);
                    break;
                case 16:
                    AddSummaryInteger("Character Count", property.Value);
                    break;
                case 18:
                    AddSummaryText("Creating Application", property.Value);
                    break;
                case 19:
                    AddSummaryInteger("Security", property.Value);
                    break;
                default:
                    MarkIncomplete(
                        $"Summary property {property.PropertyId} was present but unsupported.",
                        ArtifactCompleteness.Unsupported);
                    break;
            }
        }
    }

    private void MapRow(
        MsiTableDefinition definition,
        MsiRow row,
        IMsiDatabaseReader database)
    {
        if (ReferenceEquals(definition, MsiTables.Property))
        {
            MapProperty(row);
        }
        else if (ReferenceEquals(definition, MsiTables.Directory))
        {
            MapDirectory(row);
        }
        else if (ReferenceEquals(definition, MsiTables.Component))
        {
            AddFact(
                "msi.component",
                $"Component display-only key '{Text(row, 0)}' declares component id '{Text(row, 1)}', " +
                $"directory key '{Text(row, 2)}', raw attributes {Integer(row, 3)}, condition " +
                $"'{Text(row, 4)}', and key-path key '{Text(row, 5)}'. These values were not resolved or executed.",
                ParserConfidence.High);
        }
        else if (ReferenceEquals(definition, MsiTables.Feature))
        {
            AddFact(
                "msi.feature",
                $"Feature display-only key '{Text(row, 0)}' declares parent '{Text(row, 1)}', title " +
                $"'{Text(row, 2)}', description '{Text(row, 3)}', raw display {Integer(row, 4)}, " +
                $"raw level {Integer(row, 5)}, directory key '{Text(row, 6)}', and raw attributes {Integer(row, 7)}.",
                ParserConfidence.High);
        }
        else if (ReferenceEquals(definition, MsiTables.FeatureComponents))
        {
            AddFact(
                "msi.feature-component",
                $"Feature display-only key '{Text(row, 0)}' references component display-only key '{Text(row, 1)}'.",
                ParserConfidence.High);
        }
        else if (ReferenceEquals(definition, MsiTables.File))
        {
            AddFact(
                "msi.file",
                $"File display-only key '{Text(row, 0)}' for component key '{Text(row, 1)}' declares name " +
                $"'{Text(row, 2)}', size {Integer(row, 3)}, version '{Text(row, 4)}', language " +
                $"'{Text(row, 5)}', raw attributes {Integer(row, 6)}, and sequence {Integer(row, 7)}. " +
                "The name was not used as a filesystem path.",
                ParserConfidence.High);
        }
        else if (ReferenceEquals(definition, MsiTables.Media))
        {
            MapMedia(row);
        }
        else if (ReferenceEquals(definition, MsiTables.MsiFileHash))
        {
            AddFact(
                "msi.file-hash",
                $"File-hash row for display-only file key '{Text(row, 0)}' declares raw options " +
                $"{Integer(row, 1)} and raw parts {Integer(row, 2)}, {Integer(row, 3)}, " +
                $"{Integer(row, 4)}, {Integer(row, 5)}.",
                ParserConfidence.High);
        }
        else if (ReferenceEquals(definition, MsiTables.Binary)
            || ReferenceEquals(definition, MsiTables.Icon)
            || ReferenceEquals(definition, MsiTables.Streams)
            || ReferenceEquals(definition, MsiTables.Storages))
        {
            MapStream(definition, row, database);
        }
    }

    private void MapProperty(MsiRow row)
    {
        var key = Text(row, 0);
        var value = Text(row, 1);
        if (string.Equals(row.Fields[0].Identity, "ALLUSERS", StringComparison.Ordinal))
        {
            AddFact(
                "msi.property",
                $"Property ALLUSERS declares value '{value}'; install context remains uncertain until Windows Installer policy and invocation context are known.",
                ParserConfidence.High);
            return;
        }
        if (string.Equals(
                row.Fields[0].Identity,
                "SecureCustomProperties",
                StringComparison.Ordinal))
        {
            AddFact(
                "msi.property",
                $"Property SecureCustomProperties declares which public properties may cross into deferred or elevated context: '{value}'. This metadata is not proof that elevation occurs.",
                ParserConfidence.High);
            return;
        }

        AddFact(
            "msi.property",
            $"Property display-only key '{key}' declares value '{value}'.",
            ParserConfidence.High);
    }

    private void MapDirectory(MsiRow row)
    {
        var key = row.Fields[0].Identity!;
        if (!directories.TryAdd(
                key,
                new MsiDirectoryRow(
                    key,
                    row.Fields[1].Identity,
                    row.Fields[2].Text!.DisplayText)))
        {
            MarkIncomplete(
                "The Directory table contained a duplicate raw identity.",
                ArtifactCompleteness.Malformed);
        }
    }

    private void ResolveDirectories()
    {
        foreach (var pair in directories)
        {
            var resolution = MsiDirectoryResolver.Resolve(pair.Key, directories, limits);
            // The dictionary is keyed by the row's own raw identity, so the display key is
            // always derived from that same identity.
            var key = MsiTextPolicy.Sanitize(pair.Key, limits.MaxTextScalars).DisplayText;
            AddFact(
                "msi.directory",
                $"Directory display-only key '{key}' resolves to display-only path " +
                $"'{resolution.DisplayPath}' with status {resolution.Status}; it was not used as a filesystem path.",
                ParserConfidence.High);
            if (resolution.Status != MsiDirectoryStatus.Complete)
            {
                MarkIncomplete(
                    $"Directory relationship status {resolution.Status} prevented complete path reconstruction.",
                    resolution.Status is MsiDirectoryStatus.DepthExceeded
                        or MsiDirectoryStatus.LengthExceeded
                        ? ArtifactCompleteness.TruncatedByPolicy
                        : ArtifactCompleteness.Malformed);
            }
        }
    }

    private void MapMedia(MsiRow row)
    {
        AddFact(
            "msi.media",
            $"Media disk {Integer(row, 0)} declares last sequence {Integer(row, 1)}, prompt " +
            $"'{Text(row, 2)}', cabinet '{Text(row, 3)}', volume label '{Text(row, 4)}', and " +
            $"display-only source '{Text(row, 5)}'. No source or cabinet path was resolved.",
            ParserConfidence.High);

        var cabinetRaw = row.Fields[3].Identity;
        if (cabinetRaw is null) return;
        if (cabinetRaw.StartsWith('#'))
        {
            embeddedCabinets.Add((
                cabinetRaw[1..],
                row.Fields[3].Text!.DisplayText.TrimStart('#')));
        }
        else
        {
            MarkIncomplete(
                "An external cabinet was declared but was not resolved or opened during local static analysis.",
                ArtifactCompleteness.Unavailable);
        }
    }

    private void MapStream(
        MsiTableDefinition definition,
        MsiRow row,
        IMsiDatabaseReader database)
    {
        var key = row.Fields[0];
        var displayKey = key.Text!.DisplayText;
        var kind = ReferenceEquals(definition, MsiTables.Binary)
            ? "msi.binary"
            : ReferenceEquals(definition, MsiTables.Icon)
                ? "msi.icon"
                : ReferenceEquals(definition, MsiTables.Streams)
                    ? "msi.stream"
                    : "msi.storage";
        AddFact(
            kind,
            $"{definition.Name} contains display-only stream key '{displayKey}'; content is read only through the bounded exact-identity stream path.",
            ParserConfidence.High);

        var entry = CreateStreamEntry(definition, key, displayKey, database);
        entries.Add(entry);
        if (ReferenceEquals(definition, MsiTables.Streams))
        {
            if (!streams.TryAdd(
                    key.Identity!,
                    new StreamReference(definition, key, displayKey, database)))
            {
                MarkIncomplete(
                    "The _Streams table contained a duplicate raw identity.",
                    ArtifactCompleteness.Malformed);
            }
        }
    }

    private void CorrelateEmbeddedCabinets()
    {
        foreach (var cabinet in embeddedCabinets)
        {
            if (!streams.TryGetValue(cabinet.RawName, out var stream))
            {
                AddFact(
                    "msi.embedded-cab",
                    $"Embedded cabinet display-only key '{cabinet.DisplayName}' did not have an exact raw-identity match in _Streams.",
                    ParserConfidence.High);
                MarkIncomplete(
                    "A declared embedded cabinet could not be read from _Streams.",
                    ArtifactCompleteness.Unavailable);
                continue;
            }

            AddFact(
                "msi.embedded-cab",
                $"Embedded cabinet display-only key '{cabinet.DisplayName}' matched _Streams by complete raw identity and is supplied as a lazy graph entry.",
                ParserConfidence.High);
            entries.Add(CreateStreamEntry(
                stream.Definition,
                stream.Key,
                "embedded-cab-" + cabinet.DisplayName,
                stream.Database));
        }
    }

    private ContainerEntry CreateStreamEntry(
        MsiTableDefinition definition,
        MsiRecordValue key,
        string displayName,
        IMsiDatabaseReader database)
    {
        var claimed = MsiTextPolicy.Sanitize(
            definition.Name.TrimStart('_') + "/" + displayName,
            limits.MaxTextScalars).DisplayText;
        return new ContainerEntry(
            claimed,
            -1,
            -1,
            () => database.OpenStream(definition, [key]));
    }

    private bool ValidateRow(MsiTableDefinition definition, MsiRow row)
    {
        for (var index = 0; index < definition.Columns.Length; index++)
        {
            var column = definition.Columns[index];
            var value = row.Fields[index];
            if (column.Type == MsiColumnType.Stream) continue;
            if (!value.IsComplete)
            {
                MarkIncomplete(
                    value.IncompleteReason
                        ?? $"MSI field {definition.Name}.{column.Name} was unreadable.",
                    ArtifactCompleteness.Malformed);
                return false;
            }
            if (value.Kind == MsiValueKind.Null)
            {
                if (column.IsNullable) continue;
                MarkIncomplete(
                    $"Required MSI field {definition.Name}.{column.Name} was null.",
                    ArtifactCompleteness.Malformed);
                return false;
            }
            var expected = column.Type == MsiColumnType.Integer
                ? MsiValueKind.Integer
                : MsiValueKind.String;
            if (value.Kind != expected
                || expected == MsiValueKind.String
                    && (value.Text is null || value.Identity is null)
                || expected == MsiValueKind.Integer && value.Integer is null)
            {
                MarkIncomplete(
                    $"MSI field {definition.Name}.{column.Name} had an unexpected value kind.",
                    ArtifactCompleteness.Malformed);
                return false;
            }
        }
        return true;
    }

    private static void RecordMetricScalars(MsiRow row, int[] maxScalars)
    {
        var count = Math.Min(row.Fields.Length, maxScalars.Length);
        for (var index = 0; index < count; index++)
        {
            if (row.Fields[index].Text is { } text)
                maxScalars[index] = Math.Max(maxScalars[index], text.OriginalScalars);
        }
    }

    private void AddSummaryText(string label, MsiRecordValue value)
    {
        if (value.Kind != MsiValueKind.String || value.Text is null)
        {
            MarkIncomplete(
                $"Summary {label} had an unexpected value kind.",
                ArtifactCompleteness.Malformed);
            return;
        }
        AddFact("msi.summary", $"Summary {label}: {value.Text.DisplayText}.", ParserConfidence.High);
    }

    private void AddSummaryInteger(string label, MsiRecordValue value)
    {
        if (value.Kind != MsiValueKind.Integer || value.Integer is null)
        {
            MarkIncomplete(
                $"Summary {label} had an unexpected value kind.",
                ArtifactCompleteness.Malformed);
            return;
        }
        AddFact(
            "msi.summary",
            $"Summary {label}: {value.Integer.Value.ToString(CultureInfo.InvariantCulture)}.",
            ParserConfidence.High);
    }

    private void AddSummaryDuration(MsiRecordValue value)
    {
        if (value.Kind != MsiValueKind.FileTime || value.Duration is null)
        {
            MarkIncomplete(
                "Summary Edit Time had an unexpected value kind.",
                ArtifactCompleteness.Malformed);
            return;
        }
        AddFact(
            "msi.summary",
            $"Summary Edit Time duration: {value.Duration.Value:c}.",
            ParserConfidence.High);
    }

    private void AddSummaryTimestamp(string label, MsiRecordValue value)
    {
        if (value.Kind != MsiValueKind.FileTime || value.Timestamp is null)
        {
            MarkIncomplete(
                $"Summary {label} timestamp had an unexpected value kind.",
                ArtifactCompleteness.Malformed);
            return;
        }
        AddFact(
            "msi.summary",
            $"Summary {label} timestamp: {value.Timestamp.Value:O}.",
            ParserConfidence.High);
    }

    private void AddWordCount(MsiRecordValue value)
    {
        if (value.Kind != MsiValueKind.Integer || value.Integer is null)
        {
            MarkIncomplete(
                "Summary Word Count flags had an unexpected value kind.",
                ArtifactCompleteness.Malformed);
            return;
        }

        var raw = value.Integer.Value;
        var labels = new List<string>();
        if ((raw & 1) != 0) labels.Add("short file names");
        if ((raw & 2) != 0) labels.Add("compressed source");
        if ((raw & 4) != 0) labels.Add("administrative image");
        if ((raw & 8) != 0) labels.Add("least-privilege-compatible package");
        var declaration = labels.Count == 0
            ? "none of the known source-form flags are declared"
            : string.Join(", ", labels.Take(labels.Count - 1))
                + (labels.Count > 1 ? ", and " : string.Empty)
                + labels[^1]
                + " are declared";
        AddFact(
            "msi.summary",
            $"Summary Word Count flags: raw {raw.ToString(CultureInfo.InvariantCulture)}; {declaration}.",
            ParserConfidence.High);
        if (raw < 0 || (raw & ~15) != 0)
        {
            MarkIncomplete(
                $"Summary Word Count retained unknown raw flag value {raw.ToString(CultureInfo.InvariantCulture)}.",
                ArtifactCompleteness.Unsupported);
        }
    }

    private void AddFact(string kind, string description, ParserConfidence confidence)
    {
        var bounded = MsiTextPolicy.Sanitize(description, ContractLimits.MaxStringLength);
        facts.Add(new ArtifactObservationFact(kind, bounded.DisplayText, confidence));
        if (bounded.WasTruncated)
        {
            complete = false;
            completeness = MoreIncomplete(
                completeness,
                ArtifactCompleteness.TruncatedByPolicy);
            facts.Add(new ArtifactObservationFact(
                "msi.incomplete",
                "An MSI evidence description exceeded the configured scalar limit.",
                ParserConfidence.High));
        }
    }

    private static string Text(MsiRow row, int index) =>
        row.Fields[index].Kind == MsiValueKind.Null
            ? "not declared"
            : row.Fields[index].Text!.DisplayText;

    private static string Integer(MsiRow row, int index) =>
        row.Fields[index].Kind == MsiValueKind.Null
            ? "not declared"
            : row.Fields[index].Integer!.Value.ToString(CultureInfo.InvariantCulture);

    private static ArtifactCompleteness MoreIncomplete(
        ArtifactCompleteness left,
        ArtifactCompleteness right) =>
        Rank(left) >= Rank(right) ? left : right;

    private static int Rank(ArtifactCompleteness value) => value switch
    {
        ArtifactCompleteness.Complete => 0,
        ArtifactCompleteness.TruncatedByPolicy => 1,
        ArtifactCompleteness.Unsupported => 2,
        ArtifactCompleteness.Encrypted => 3,
        ArtifactCompleteness.Malformed => 4,
        ArtifactCompleteness.Unavailable => 5,
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };

    private sealed record StreamReference(
        MsiTableDefinition Definition,
        MsiRecordValue Key,
        string DisplayName,
        IMsiDatabaseReader Database);
}
