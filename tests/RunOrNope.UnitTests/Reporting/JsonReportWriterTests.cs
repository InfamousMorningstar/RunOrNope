using System.Text;
using System.Text.Json;
using System.Collections.Immutable;
using AwesomeAssertions;
using RunOrNope.Contracts;
using RunOrNope.Reporting;
using RunOrNope.Rules;
using Xunit;

namespace RunOrNope.UnitTests.Reporting;

public sealed class JsonReportWriterTests
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    [Fact]
    public void Write_EmitsVersionedReproducibleEnvelope()
    {
        var bytes = JsonReportWriter.Write(ReportTestData.Complete());
        using var document = JsonDocument.Parse(bytes);
        var root = document.RootElement;

        root.GetProperty("schemaVersion").GetString().Should().Be("runornope-report-1");
        root.GetProperty("reproducibility").GetProperty("rulesVersion").GetString()
            .Should().Be(CapabilityRuleEngine.RulesVersion);
        root.GetProperty("reproducibility").GetProperty("contractLimits")
            .GetProperty("maxJsonBytes").GetInt32().Should().Be(ContractLimits.MaxJsonBytes);
        root.GetProperty("verdict").GetProperty("analysisStatus").GetString().Should().Be("complete");
        root.GetProperty("scanResult").GetProperty("artifacts")[0].GetProperty("sha256").GetString()
            .Should().Be(ReportTestData.Sha);
        root.GetProperty("scanResult").GetProperty("findings")[0].GetProperty("observationIds")[0]
            .GetString().Should().Be("obs-1");
    }

    [Fact]
    public void Write_IsDeterministicValidUtf8WithoutBom()
    {
        var result = ReportTestData.WithSampleName("emoji-😀.exe");

        var first = JsonReportWriter.Write(result);
        var second = JsonReportWriter.Write(result);

        first.Should().Equal(second);
        first.Take(3).SequenceEqual(new byte[] { 0xEF, 0xBB, 0xBF }).Should().BeFalse();
        StrictUtf8.GetString(first).Should().Contain("emoji-");
    }

    [Fact]
    public void Write_RejectsDuplicateEvidenceAndOverLimitText()
    {
        var duplicate = ReportTestData.Complete() with
        {
            Findings =
            [
                ReportTestData.Complete().Findings[0] with { ObservationIds = ["obs-1", "obs-1"] }
            ]
        };
        var huge = ReportTestData.WithSampleName(new string('x', ContractLimits.MaxStringLength + 1));

        ((Action)(() => JsonReportWriter.Write(duplicate))).Should().Throw<ContractValidationException>();
        ((Action)(() => JsonReportWriter.Write(huge))).Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Write_IncompleteAnalysisKeepsDispositionSeparateAndNullable()
    {
        var result = ReportTestData.Complete() with
        {
            AnalysisStatus = AnalysisStatus.Incomplete,
            Completeness = ArtifactCompleteness.TruncatedByPolicy,
            Artifacts =
            [
                ReportTestData.Complete().Artifacts[0] with
                {
                    Completeness = ArtifactCompleteness.TruncatedByPolicy
                }
            ],
            Findings = [],
        };

        using var document = JsonDocument.Parse(JsonReportWriter.Write(result));
        var verdict = document.RootElement.GetProperty("verdict");

        verdict.GetProperty("analysisStatus").GetString().Should().Be("incomplete");
        verdict.GetProperty("riskDisposition").ValueKind.Should().Be(JsonValueKind.Null);
    }

    [Fact]
    public void Write_RejectsInvalidEvidenceMode()
    {
        var options = new ReportOptions((ReportEvidenceMode)99);

        ((Action)(() => JsonReportWriter.Write(ReportTestData.Complete(), options)))
            .Should().Throw<ArgumentOutOfRangeException>();
    }

    [Fact]
    public void Write_AggregatesRecommendedActionByDeclaredEscalationOrder()
    {
        var template = ReportTestData.Complete();
        var findings = ImmutableArray.Create(
            template.Findings[0] with { RecommendedAction = RecommendedAction.DoNotRunAndEscalate },
            template.Findings[0] with { RecommendedAction = RecommendedAction.ReviewProvenance },
            template.Findings[0] with { RecommendedAction = RecommendedAction.ExerciseCaution });
        var result = template with { Findings = findings };

        using var document = JsonDocument.Parse(JsonReportWriter.Write(result));

        document.RootElement.GetProperty("verdict").GetProperty("recommendedAction")
            .GetString().Should().Be("do-not-run-and-escalate");
    }
}
