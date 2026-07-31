using System.Collections.Immutable;
using AwesomeAssertions;
using RunOrNope.Analyzers.Content;
using RunOrNope.Analyzers.Msi;
using RunOrNope.Contracts;
using Xunit;

namespace RunOrNope.Tests.Msi;

public sealed class MsiPackageInventoryTests
{
    private const string Sha256 =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    [Fact]
    public void Property_family_reports_install_context_uncertainty_and_secure_property_boundary()
    {
        using var fixture = new MsiFixtureBuilder()
            .AddTable(
                "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` CHAR(0) " +
                "PRIMARY KEY `Property`)")
            .Insert(
                "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)",
                "ALLUSERS",
                "2")
            .Insert(
                "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)",
                "SecureCustomProperties",
                "SAFE_ONE;SAFE_TWO");
        var result = Analyze(fixture.Commit());

        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.property"
            && observation.Description.Contains("ALLUSERS", StringComparison.Ordinal)
            && observation.Description.Contains("context remains uncertain", StringComparison.Ordinal));
        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.property"
            && observation.Description.Contains("SecureCustomProperties", StringComparison.Ordinal)
            && observation.Description.Contains("deferred or elevated context", StringComparison.Ordinal));
        AssertMetricsDoNotLeak(result, "ALLUSERS", "SAFE_ONE", "SAFE_TWO");
    }

    [Fact]
    public void Directory_family_uses_bounded_display_only_resolution()
    {
        using var fixture = new MsiFixtureBuilder()
            .AddTable(
                "CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, " +
                "`Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL " +
                "PRIMARY KEY `Directory`)")
            .Insert(
                "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) " +
                "VALUES (?, ?, ?)",
                "TARGETDIR",
                null,
                "SourceDir")
            .Insert(
                "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) " +
                "VALUES (?, ?, ?)",
                "INSTALLDIR",
                "TARGETDIR",
                "Example");
        var result = Analyze(fixture.Commit());

        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.directory"
            && observation.Description.Contains("display-only key 'INSTALLDIR'", StringComparison.Ordinal)
            && observation.Description.Contains("SourceDir\\Example", StringComparison.Ordinal)
            && observation.Description.Contains("was not used as a filesystem path", StringComparison.Ordinal));
        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
    }

    [Fact]
    public void Directory_cycle_is_reported_and_forces_incomplete()
    {
        using var fixture = new MsiFixtureBuilder()
            .AddTable(
                "CREATE TABLE `Directory` (`Directory` CHAR(72) NOT NULL, " +
                "`Directory_Parent` CHAR(72), `DefaultDir` CHAR(255) NOT NULL " +
                "PRIMARY KEY `Directory`)")
            .Insert(
                "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) " +
                "VALUES (?, ?, ?)",
                "A",
                "B",
                "Alpha")
            .Insert(
                "INSERT INTO `Directory` (`Directory`, `Directory_Parent`, `DefaultDir`) " +
                "VALUES (?, ?, ?)",
                "B",
                "A",
                "Beta");
        var result = Analyze(fixture.Commit());

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.directory"
            && observation.Description.Contains("Cycle", StringComparison.Ordinal));
    }

    [Fact]
    public void Relationship_family_retains_conditions_and_raw_unknown_integers()
    {
        using var fixture = new MsiFixtureBuilder()
            .AddTable(
                "CREATE TABLE `Component` (`Component` CHAR(72) NOT NULL, `ComponentId` CHAR(38), " +
                "`Directory_` CHAR(72) NOT NULL, `Attributes` LONG NOT NULL, `Condition` CHAR(255), " +
                "`KeyPath` CHAR(72) PRIMARY KEY `Component`)")
            .AddTable(
                "CREATE TABLE `Feature` (`Feature` CHAR(38) NOT NULL, `Feature_Parent` CHAR(38), " +
                "`Title` CHAR(64), `Description` CHAR(255), `Display` SHORT, `Level` SHORT NOT NULL, " +
                "`Directory_` CHAR(72), `Attributes` LONG NOT NULL PRIMARY KEY `Feature`)")
            .AddTable(
                "CREATE TABLE `FeatureComponents` (`Feature_` CHAR(38) NOT NULL, " +
                "`Component_` CHAR(72) NOT NULL PRIMARY KEY `Feature_`, `Component_`)")
            .Insert(
                "INSERT INTO `Component` (`Component`, `ComponentId`, `Directory_`, `Attributes`, " +
                "`Condition`, `KeyPath`) VALUES (?, ?, ?, ?, ?, ?)",
                "CmpOne",
                "{00000000-0000-0000-0000-000000000002}",
                "INSTALLDIR",
                int.MaxValue,
                "VersionNT64 AND FEATURE=1",
                "FileOne")
            .Insert(
                "INSERT INTO `Feature` (`Feature`, `Feature_Parent`, `Title`, `Description`, `Display`, " +
                "`Level`, `Directory_`, `Attributes`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                "MainFeature",
                null,
                "Main",
                "Synthetic feature",
                -7,
                1,
                "INSTALLDIR",
                int.MaxValue)
            .Insert(
                "INSERT INTO `FeatureComponents` (`Feature_`, `Component_`) VALUES (?, ?)",
                "MainFeature",
                "CmpOne");
        var result = Analyze(fixture.Commit());

        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.component"
            && observation.Description.Contains("VersionNT64 AND FEATURE=1", StringComparison.Ordinal)
            && observation.Description.Contains($"raw attributes {int.MaxValue}", StringComparison.Ordinal));
        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.feature"
            && observation.Description.Contains("raw display -7", StringComparison.Ordinal)
            && observation.Description.Contains($"raw attributes {int.MaxValue}", StringComparison.Ordinal));
        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.feature-component");
    }

    [Fact]
    public void File_media_and_hash_families_inventory_every_declared_scalar()
    {
        using var fixture = new MsiFixtureBuilder()
            .AddTable(
                "CREATE TABLE `File` (`File` CHAR(72) NOT NULL, `Component_` CHAR(72) NOT NULL, " +
                "`FileName` CHAR(255) NOT NULL, `FileSize` LONG NOT NULL, `Version` CHAR(72), " +
                "`Language` CHAR(20), `Attributes` SHORT, `Sequence` LONG NOT NULL PRIMARY KEY `File`)")
            .AddTable(
                "CREATE TABLE `Media` (`DiskId` SHORT NOT NULL, `LastSequence` LONG NOT NULL, " +
                "`DiskPrompt` CHAR(64), `Cabinet` CHAR(255), `VolumeLabel` CHAR(32), " +
                "`Source` CHAR(72) PRIMARY KEY `DiskId`)")
            .AddTable(
                "CREATE TABLE `MsiFileHash` (`File_` CHAR(72) NOT NULL, `Options` SHORT NOT NULL, " +
                "`HashPart1` LONG NOT NULL, `HashPart2` LONG NOT NULL, `HashPart3` LONG NOT NULL, " +
                "`HashPart4` LONG NOT NULL PRIMARY KEY `File_`)")
            .Insert(
                "INSERT INTO `File` (`File`, `Component_`, `FileName`, `FileSize`, `Version`, " +
                "`Language`, `Attributes`, `Sequence`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                "FileOne",
                "CmpOne",
                "example.txt",
                12,
                "1.2.3.4",
                "1033",
                16384,
                1)
            .Insert(
                "INSERT INTO `Media` (`DiskId`, `LastSequence`, `DiskPrompt`, `Cabinet`, " +
                "`VolumeLabel`, `Source`) VALUES (?, ?, ?, ?, ?, ?)",
                1,
                1,
                "Insert media",
                "external.cab",
                "SYNTHETIC",
                "media")
            .Insert(
                "INSERT INTO `MsiFileHash` (`File_`, `Options`, `HashPart1`, `HashPart2`, " +
                "`HashPart3`, `HashPart4`) VALUES (?, ?, ?, ?, ?, ?)",
                "FileOne",
                0,
                1,
                2,
                3,
                4);
        var result = Analyze(fixture.Commit());

        result.Observations.Should().Contain(observation => observation.Kind == "msi.file");
        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.media"
            && observation.Description.Contains("external.cab", StringComparison.Ordinal));
        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.file-hash"
            && observation.Description.Contains("raw parts 1, 2, 3, 4", StringComparison.Ordinal));
    }

    [Fact]
    public void Stream_family_is_consumed_lazily_while_database_is_alive()
    {
        var reader = new LifetimeCheckingReader();
        var analyzer = new MsiAnalyzer(MsiAnalysisLimits.Default, new SingleReaderFactory(reader));

        var result = analyzer.Analyze(
            new MsiRootInput("synthetic.msi", Sha256, 44),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

        result.Observations.Select(observation => observation.Kind).Should().Contain(
            ["msi.binary", "msi.icon", "msi.stream", "msi.storage"]);
        result.Artifacts.Should().HaveCount(5);
        reader.StreamsOpened.Should().Be(4);
        reader.Disposed.Should().BeTrue();
    }

    [Fact]
    public void Embedded_cabinet_correlation_uses_raw_exact_stream_identity_and_graph_deduplication()
    {
        var reader = new EmbeddedCabReader();
        var result = Analyze(reader);

        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.embedded-cab"
            && observation.Description.Contains("display-only", StringComparison.Ordinal));
        result.Observations.Should().Contain(observation =>
            observation.Kind == "artifact.duplicate");
        result.Artifacts.Should().HaveCount(2);
    }

    [Fact]
    public void Unknown_present_table_is_unsupported_and_forces_incomplete()
    {
        var reader = new ConfigurableReader(["UnexaminedCustomTable"]);
        var analyzer = new MsiAnalyzer(MsiAnalysisLimits.Default, new SingleReaderFactory(reader));

        var result = analyzer.Analyze(
            new MsiRootInput("synthetic.msi", Sha256, 0),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.table-unsupported"
            && observation.Description.Contains("UnexaminedCustomTable", StringComparison.Ordinal));
        ContractValidator.Validate(result);
    }

    [Fact]
    public void Absent_optional_tables_are_complete_but_unreadable_present_table_is_not()
    {
        var absent = Analyze(new ConfigurableReader([]));
        var unreadable = Analyze(new ConfigurableReader(["Property"])
        {
            QueryFailure = new MsiDataIncompleteException("Injected present-table read failure."),
        });

        absent.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        unreadable.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        unreadable.Observations.Should().Contain(observation =>
            observation.Kind == "msi.incomplete"
            && observation.Description.Contains("present-table", StringComparison.Ordinal));
    }

    private static ScanResult Analyze(string path) =>
        new MsiAnalyzer().Analyze(
            new MsiRootInput(path, Sha256, new FileInfo(path).Length),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

    private static ScanResult Analyze(IMsiDatabaseReader reader) =>
        new MsiAnalyzer(MsiAnalysisLimits.Default, new SingleReaderFactory(reader)).Analyze(
            new MsiRootInput("synthetic.msi", Sha256, 0),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

    private static void AssertMetricsDoNotLeak(ScanResult result, params string[] forbidden)
    {
        var metrics = result.Observations
            .Where(observation => observation.Kind == "msi.inventory-metrics")
            .Select(observation => observation.Description)
            .ToArray();
        metrics.Should().NotBeEmpty();
        foreach (var value in forbidden)
        {
            metrics.Should().AllSatisfy(metric =>
                metric.Should().NotContain(value));
        }
    }

    private sealed class UnusedMaterializationService : IMsiMaterializationService
    {
        public IMsiMaterializedFile Materialize(
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Task 5 inventory must not materialize content.");
    }

    private sealed class SingleReaderFactory(IMsiDatabaseReader reader) : IMsiDatabaseFactory
    {
        public IMsiDatabaseReader OpenReadOnly(string path) => reader;
    }

    private class ConfigurableReader(ImmutableArray<string> tables) : IMsiDatabaseReader
    {
        internal Exception? QueryFailure { get; init; }

        public ImmutableArray<string> EnumerateTables(
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken) => tables;

        public virtual IEnumerable<MsiRow> Query(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> parameters,
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken)
        {
            if (QueryFailure is not null) throw QueryFailure;
            return [];
        }

        public ImmutableArray<MsiSummaryProperty> ReadSummary(
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken) => [];

        public virtual Stream OpenStream(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> keyParameters) =>
            throw new InvalidOperationException();

        public virtual void Dispose()
        {
        }
    }

    private sealed class LifetimeCheckingReader()
        : ConfigurableReader(["Binary", "Icon", "_Streams", "_Storages"])
    {
        private bool disposed;

        internal int StreamsOpened { get; private set; }
        internal bool Disposed => disposed;

        public override IEnumerable<MsiRow> Query(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> parameters,
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return
            [
                new MsiRow(
                [
                    new MsiRecordValue(
                        MsiValueKind.String,
                        null,
                        MsiTextPolicy.Sanitize(
                            definition.Name + "-key",
                            MsiAnalysisLimits.Default.MaxTextScalars),
                        null,
                        Identity: definition.Name + "-key"),
                    new MsiRecordValue(MsiValueKind.Stream, null, null, null, false),
                ]),
            ];
        }

        public override Stream OpenStream(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> keyParameters)
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            StreamsOpened++;
            return new MemoryStream([(byte)StreamsOpened]);
        }

        public override void Dispose()
        {
            disposed = true;
            base.Dispose();
        }
    }

    private sealed class EmbeddedCabReader()
        : ConfigurableReader(["Media", "_Streams"])
    {
        public override IEnumerable<MsiRow> Query(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> parameters,
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken) =>
            ReferenceEquals(definition, MsiTables.Media)
                ?
                [
                    new MsiRow(
                    [
                        Integer(1),
                        Integer(1),
                        Null(),
                        Text("#cab-one"),
                        Null(),
                        Null(),
                    ]),
                ]
                :
                [
                    new MsiRow(
                    [
                        Text("cab-one"),
                        new MsiRecordValue(MsiValueKind.Stream, null, null, null, false),
                    ]),
                ];

        public override Stream OpenStream(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> keyParameters) =>
            new MemoryStream([1, 2, 3, 4]);

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
    }
}
