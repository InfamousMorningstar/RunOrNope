using AwesomeAssertions;
using RunOrNope.App.ViewModels;
using RunOrNope.Contracts;
using Xunit;

namespace RunOrNope.UnitTests.App;

public sealed class CapabilityCardViewModelTests
{
    [Fact]
    public void From_PreservesEvidenceTierAndExactSource()
    {
        var result = AppTestData.ScanResult(
            severity: Severity.Informational,
            status: EvidenceStatus.ApiOrLibraryPresenceOnly,
            confidence: EvidenceConfidence.Low,
            offset: 4096,
            region: "imports");

        var card = CapabilityCardViewModel.From(result, result.Findings[0]);

        card.ContextLabel.Should().Be("Context — API or library presence only");
        card.Severity.Should().Be("Informational");
        card.EvidenceStatus.Should().Be("ApiOrLibraryPresenceOnly");
        card.EvidenceConfidence.Should().Be("Low");
        card.Sources.Should().ContainSingle().Which.Should().Be("obs-1 · sample.exe · offset 4096 · imports");
        card.BenignExplanations.Should().Contain("Common in diagnostic software.");
        card.Limitations.Should().Contain("Presence does not prove use.");
    }

    [Fact]
    public void From_StrongStructuralHighUsesCautionLabel()
    {
        var result = AppTestData.ScanResult(
            severity: Severity.High,
            status: EvidenceStatus.StrongStructuralEvidence,
            confidence: EvidenceConfidence.High);

        CapabilityCardViewModel.From(result, result.Findings[0]).ContextLabel
            .Should().Be("Caution — strong structural evidence");
    }
}

internal static class AppTestData
{
    internal const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    internal static ScanResult ScanResult(
        Severity severity = Severity.Informational,
        EvidenceStatus status = EvidenceStatus.ApiOrLibraryPresenceOnly,
        EvidenceConfidence confidence = EvidenceConfidence.Low,
        long? offset = null,
        string? region = null) =>
        new(
            "sample.exe", AnalysisStatus.Complete, ArtifactCompleteness.Complete,
            [new ArtifactNode("root", "sample.exe", Sha, 128, ArtifactCompleteness.Complete, [], ApplicationLinkage.Application)],
            [new Observation("obs-1", "pe.import", "kernel32!IsDebuggerPresent",
                ParserConfidence.High, new SourceLocation("root", offset, region))],
            [new CapabilityFinding(
                status == EvidenceStatus.StrongStructuralEvidence
                    ? "Injects code into another process" : "Checks for a debugger",
                "Potential impact", RiskFamily.DefenseEvasion, status,
                ParserConfidence.High, confidence, severity, ApplicationLinkage.Application,
                Reachability.Referenced, ["obs-1"], ["Common in diagnostic software."],
                ["Presence does not prove use."], RecommendedAction.ReviewProvenance)],
            []);
}
