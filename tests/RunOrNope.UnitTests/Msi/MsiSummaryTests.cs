using System.Collections.Immutable;
using AwesomeAssertions;
using RunOrNope.Analyzers.Content;
using RunOrNope.Analyzers.Msi;
using RunOrNope.Contracts;
using RunOrNope.Core.Verdicts;
using Xunit;

namespace RunOrNope.Tests.Msi;

public sealed class MsiSummaryTests
{
    private const string Sha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void Complete_summary_preserves_every_supported_property_with_native_semantics()
    {
        var created = new DateTimeOffset(2025, 3, 4, 5, 6, 7, TimeSpan.Zero);
        var saved = new DateTimeOffset(2025, 4, 5, 6, 7, 8, TimeSpan.Zero);
        using var fixture = new MsiFixtureBuilder()
            .SetSummary(2, "Benign title")
            .SetSummary(3, "Benign subject")
            .SetSummary(4, "Example author")
            .SetSummary(5, "alpha;beta")
            .SetSummary(6, "Synthetic fixture")
            .SetSummary(7, "x64;1033")
            .SetSummary(8, "Fixture builder")
            .SetSummary(9, "{00000000-0000-0000-0000-000000000001}")
            .SetSummary(12, created)
            .SetSummary(13, saved)
            .SetSummary(14, 7)
            .SetSummary(15, 15)
            .SetSummary(18, "RunOrNope tests");
        var path = fixture.Commit();

        var result = Analyze(path, size: 321);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        result.Observations.Select(item => item.Description).Should().Contain(
        [
            "Summary Title: Benign title.",
            "Summary Subject: Benign subject.",
            "Summary Author: Example author.",
            "Summary Keywords: alpha;beta.",
            "Summary Comments: Synthetic fixture.",
            "Summary Template: x64;1033.",
            "Summary Last Saved By: Fixture builder.",
            "Summary Revision Number: {00000000-0000-0000-0000-000000000001}.",
            "Summary Page Count: 7.",
            "Summary Word Count flags: raw 15; short file names, compressed source, administrative image, and least-privilege-compatible package are declared.",
            "Summary Creating Application: RunOrNope tests.",
            "Summary Created timestamp: 2025-03-04T05:06:07.0000000+00:00.",
            "Summary Last Saved timestamp: 2025-04-05T06:07:08.0000000+00:00.",
        ]);
        result.Artifacts.Single().Sha256.Should().Be(Sha256);
        result.Artifacts.Single().Size.Should().Be(321);
        result.Findings.Should().BeEmpty();
        ContractValidator.Validate(result);
    }

    [Fact]
    public void Wrong_native_summary_type_forces_incomplete_and_withholds_disposition()
    {
        var reason = "Summary property 2 used unexpected variant type 3.";
        var reader = new SummaryReader
        {
            Summary =
            [
                new MsiSummaryProperty(
                    2,
                    new MsiRecordValue(
                        MsiValueKind.Null,
                        null,
                        null,
                        null,
                        false,
                        reason),
                    false,
                    reason),
            ],
        };
        var analyzer = new MsiAnalyzer(MsiAnalysisLimits.Default, new SingleReaderFactory(reader));

        var result = analyzer.Analyze(
            new MsiRootInput("synthetic.msi", Sha256, 0),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

        AssertIncomplete(result, "unexpected variant type");
    }

    [Fact]
    public void Oversized_summary_text_is_bounded_and_forces_incomplete()
    {
        using var fixture = new MsiFixtureBuilder()
            .SetSummary(2, new string('x', MsiAnalysisLimits.Default.MaxTextScalars + 1));
        var path = fixture.Commit();

        var result = Analyze(path);

        AssertIncomplete(result, "scalar limit");
        result.Observations.Should().AllSatisfy(observation =>
            observation.Description.EnumerateRunes().Count().Should()
                .BeLessThanOrEqualTo(ContractLimits.MaxStringLength));
    }

    [Fact]
    public void Unreadable_summary_handle_forces_incomplete_with_a_bounded_reason()
    {
        var reader = new SummaryReader
        {
            SummaryFailure = new MsiDatabaseException("open summary information", 5),
        };
        var analyzer = new MsiAnalyzer(MsiAnalysisLimits.Default, new SingleReaderFactory(reader));

        var result = analyzer.Analyze(
            new MsiRootInput("synthetic.msi", Sha256, 0),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

        AssertIncomplete(result, "open summary information");
        reader.Disposed.Should().BeTrue();
    }

    [Fact]
    public void Summary_text_that_changes_while_reading_forces_incomplete()
    {
        var text = MsiTextPolicy.Sanitize("bounded", MsiAnalysisLimits.Default.MaxTextScalars);
        var reader = new SummaryReader
        {
            Summary =
            [
                new MsiSummaryProperty(
                    2,
                    new MsiRecordValue(
                        MsiValueKind.String,
                        null,
                        text,
                        null,
                        false,
                        "MSI text changed while it was being retrieved.",
                        "bounded"),
                    false,
                    "MSI text changed while it was being retrieved."),
            ],
        };
        var analyzer = new MsiAnalyzer(MsiAnalysisLimits.Default, new SingleReaderFactory(reader));

        var result = analyzer.Analyze(
            new MsiRootInput("synthetic.msi", Sha256, 0),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

        AssertIncomplete(result, "changed while");
    }

    private static ScanResult Analyze(string path, long size = 0) =>
        new MsiAnalyzer().Analyze(
            new MsiRootInput(path, Sha256, size),
            new UnusedMaterializationService(),
            null,
            TestContext.Current.CancellationToken);

    private static void AssertIncomplete(ScanResult result, string reasonFragment)
    {
        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Completeness.Should().NotBe(ArtifactCompleteness.Complete);
        result.Observations.Should().Contain(observation =>
            observation.Kind == "msi.incomplete"
            && observation.Description.Contains(reasonFragment, StringComparison.OrdinalIgnoreCase));
        ContractValidator.Validate(result);
        var restored = ScanContractJson.Deserialize(ScanContractJson.Serialize(result));
        VerdictEngine.Evaluate(restored).RiskDisposition.Should().BeNull();
    }

    private sealed class UnusedMaterializationService : IMsiMaterializationService
    {
        public IMsiMaterializedFile Materialize(
            ReadOnlyMemory<byte> content,
            CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Summary inventory must not materialize content.");
    }

    private sealed class SingleReaderFactory(IMsiDatabaseReader reader) : IMsiDatabaseFactory
    {
        public IMsiDatabaseReader OpenReadOnly(string path) => reader;
    }

    private sealed class SummaryReader : IMsiDatabaseReader
    {
        internal ImmutableArray<MsiSummaryProperty> Summary { get; init; } = [];
        internal Exception? SummaryFailure { get; init; }
        internal bool Disposed { get; private set; }

        public ImmutableArray<string> EnumerateTables(
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken) => [];

        public IEnumerable<MsiRow> Query(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> parameters,
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken) => [];

        public ImmutableArray<MsiSummaryProperty> ReadSummary(
            MsiAnalysisLimits limits,
            CancellationToken cancellationToken)
        {
            if (SummaryFailure is not null) throw SummaryFailure;
            return Summary;
        }

        public Stream OpenStream(
            MsiTableDefinition definition,
            ImmutableArray<MsiRecordValue> keyParameters) =>
            throw new InvalidOperationException();

        public void Dispose() => Disposed = true;
    }
}
