using System.Collections.Immutable;
using AwesomeAssertions;
using RunOrNope.Analyzers.Content;
using RunOrNope.Analyzers.Msi;
using RunOrNope.Contracts;
using Xunit;

namespace RunOrNope.SecurityTests.Msi;

public sealed class MsiInventoryLimitTests
{
    private const string Sha256 =
        "1111111111111111111111111111111111111111111111111111111111111111";

    [Theory]
    [InlineData(256, AnalysisStatus.Complete)]
    [InlineData(257, AnalysisStatus.Incomplete)]
    public void Table_ceiling_stops_at_the_exact_boundary_without_large_fixtures(
        int tableCount,
        AnalysisStatus expected)
    {
        var reader = new GeneratedReader(
            Enumerable.Repeat("Property", tableCount).ToImmutableArray(),
            ImmutableDictionary<string, int>.Empty);

        var result = Analyze(reader);

        result.AnalysisStatus.Should().Be(expected);
        if (expected == AnalysisStatus.Incomplete)
        {
            result.Observations.Should().Contain(observation =>
                observation.Kind == "msi.incomplete"
                && observation.Description.Contains("table limit", StringComparison.Ordinal));
        }
    }

    [Theory]
    [InlineData(8_192, AnalysisStatus.Complete)]
    [InlineData(8_193, AnalysisStatus.Incomplete)]
    public void Per_table_row_ceiling_stops_at_the_exact_boundary(
        int rowCount,
        AnalysisStatus expected)
    {
        var reader = new GeneratedReader(
            ["Property"],
            ImmutableDictionary<string, int>.Empty.Add("Property", rowCount));

        var result = Analyze(reader);

        result.AnalysisStatus.Should().Be(expected);
        reader.RowsYielded.Should().Be(rowCount);
        if (expected == AnalysisStatus.Incomplete)
        {
            result.Observations.Should().Contain(observation =>
                observation.Kind == "msi.incomplete"
                && observation.Description.Contains("row limit", StringComparison.Ordinal));
        }
    }

    [Theory]
    [InlineData(false, AnalysisStatus.Complete, 32_768)]
    [InlineData(true, AnalysisStatus.Incomplete, 32_769)]
    public void Aggregate_row_ceiling_stops_at_the_exact_boundary(
        bool includeOneMoreTable,
        AnalysisStatus expected,
        int expectedRows)
    {
        var tables = includeOneMoreTable
            ? ImmutableArray.Create("Property", "Component", "Feature", "File", "MsiFileHash")
            : ImmutableArray.Create("Property", "Component", "Feature", "File");
        var rows = ImmutableDictionary<string, int>.Empty
            .Add("Property", 8_192)
            .Add("Component", 8_192)
            .Add("Feature", 8_192)
            .Add("File", 8_192)
            .Add("MsiFileHash", 1);
        var reader = new GeneratedReader(tables, rows);

        var result = Analyze(reader);

        result.AnalysisStatus.Should().Be(expected);
        reader.RowsYielded.Should().Be(expectedRows);
        if (expected == AnalysisStatus.Incomplete)
        {
            result.Observations.Should().Contain(observation =>
                observation.Kind == "msi.incomplete"
                && observation.Description.Contains("total row limit", StringComparison.Ordinal));
        }
    }

    [Fact]
    public void Aggregate_row_ceiling_stops_enumerating_the_remaining_catalog()
    {
        // Tables after the one that exhausts the aggregate budget must not be read at all.
        // Continuing would re-charge and re-report the same exhaustion for every table left.
        var reader = new GeneratedReader(
            ["Property", "Component", "Feature", "File", "MsiFileHash", "Media"],
            ImmutableDictionary<string, int>.Empty
                .Add("Property", 8_192)
                .Add("Component", 8_192)
                .Add("Feature", 8_192)
                .Add("File", 8_192)
                .Add("MsiFileHash", 1)
                .Add("Media", 1));

        var result = Analyze(reader);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        reader.RowsYielded.Should().Be(32_769);
        reader.EnumeratedTables.Should().NotContain("Media");
        result.Observations
            .Count(observation =>
                observation.Kind == "msi.incomplete"
                && observation.Description.Contains("total row limit", StringComparison.Ordinal))
            .Should().Be(1);
    }

    [Theory]
    [InlineData(32, AnalysisStatus.Complete)]
    [InlineData(33, AnalysisStatus.Incomplete)]
    public void Field_ceiling_stops_at_the_exact_boundary(
        int fieldCount,
        AnalysisStatus expected)
    {
        var reader = new GeneratedReader(
            ["Property"],
            ImmutableDictionary<string, int>.Empty.Add("Property", 1))
        {
            OverrideFieldCount = fieldCount,
        };

        var result = Analyze(reader);

        result.AnalysisStatus.Should().Be(expected);
        if (expected == AnalysisStatus.Incomplete)
        {
            result.Observations.Should().Contain(observation =>
                observation.Kind == "msi.incomplete"
                && observation.Description.Contains("field limit", StringComparison.Ordinal));
        }
    }

    private static ScanResult Analyze(IMsiDatabaseReader reader) =>
        new MsiAnalyzer(MsiAnalysisLimits.Default, new SingleReaderFactory(reader)).Analyze(
            new MsiRootInput("synthetic.msi", Sha256, 0),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

    private static MsiRecordValue Text(string value) => new(
        MsiValueKind.String,
        null,
        MsiTextPolicy.Sanitize(value, MsiAnalysisLimits.Default.MaxTextScalars),
        null,
        Identity: value);

    private static MsiRecordValue Integer(int value) =>
        new(MsiValueKind.Integer, value, null, null);

    private static MsiRecordValue Null() =>
        new(MsiValueKind.Null, null, null, null);

    private sealed class UnusedMaterializationService : IMsiMaterializationService
    {
        public IMsiMaterializedFile Materialize(
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Limit tests do not materialize sample content.");
    }

    private sealed class SingleReaderFactory(IMsiDatabaseReader reader) : IMsiDatabaseFactory
    {
        public IMsiDatabaseReader OpenReadOnly(string path) => reader;
    }

    private sealed class GeneratedReader(
        ImmutableArray<string> tables,
        ImmutableDictionary<string, int> rowCounts) : IMsiDatabaseReader
    {
        internal int? OverrideFieldCount { get; init; }
        internal int RowsYielded { get; private set; }
        internal List<string> EnumeratedTables { get; } = [];

        public ImmutableArray<string> EnumerateTables(
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken) => tables;

        public IEnumerable<MsiRow> Query(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> parameters,
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken)
        {
            EnumeratedTables.Add(definition.Name);
            var count = rowCounts.GetValueOrDefault(definition.Name);
            for (var index = 0; index < count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                RowsYielded++;
                var row = RowFor(definition.Name);
                if (OverrideFieldCount is { } fieldCount)
                {
                    var fields = row.Fields.ToBuilder();
                    while (fields.Count < fieldCount) fields.Add(Null());
                    if (fields.Count > fieldCount)
                        fields.RemoveRange(fieldCount, fields.Count - fieldCount);
                    row = new MsiRow(fields.ToImmutable());
                }
                yield return row;
            }
        }

        public ImmutableArray<MsiSummaryProperty> ReadSummary(
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken) => [];

        public Stream OpenStream(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> keyParameters) =>
            throw new InvalidOperationException();

        public void Dispose()
        {
        }

        private static MsiRow RowFor(string table) => table switch
        {
            "Property" => new MsiRow([Text("P"), Text("V")]),
            "Component" => new MsiRow(
                [Text("C"), Null(), Text("D"), Integer(0), Null(), Null()]),
            "Feature" => new MsiRow(
                [Text("F"), Null(), Null(), Null(), Integer(0), Integer(1), Null(), Integer(0)]),
            "File" => new MsiRow(
                [Text("File"), Text("C"), Text("f"), Integer(1), Null(), Null(), Null(), Integer(1)]),
            "MsiFileHash" => new MsiRow(
                [Text("File"), Integer(0), Integer(1), Integer(2), Integer(3), Integer(4)]),
            // Cabinet is null, so no embedded/external media correlation is triggered.
            "Media" => new MsiRow(
                [Integer(1), Integer(1), Null(), Null(), Null(), Null()]),
            _ => throw new InvalidOperationException($"No generated row for fixed table {table}."),
        };
    }
}
