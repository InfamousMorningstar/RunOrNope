using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.UnitTests.Reporting;

internal static class ReportTestData
{
    internal const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    internal static ScanResult Complete(string text = "ordinary evidence") =>
        new(
            "sample.exe",
            AnalysisStatus.Complete,
            ArtifactCompleteness.Complete,
            [new ArtifactNode("root", "sample.exe", Sha, 123, ArtifactCompleteness.Complete, [], ApplicationLinkage.Unknown)],
            [new Observation("obs-1", "test.kind", text, ParserConfidence.High, new SourceLocation("root", 12, "header"))],
            [new CapabilityFinding(
                "Test capability",
                text,
                RiskFamily.NetworkCommunication,
                EvidenceStatus.ApiOrLibraryPresenceOnly,
                ParserConfidence.High,
                EvidenceConfidence.Medium,
                Severity.Informational,
                ApplicationLinkage.Unknown,
                Reachability.Referenced,
                ["obs-1"],
                ["May be ordinary application behavior."],
                ["Static evidence does not prove use."],
                RecommendedAction.ReviewProvenance)],
            ["Valid signature was not established."]);

    internal static ScanResult WithSampleName(string sampleName) => Complete() with { SampleName = sampleName };
}
