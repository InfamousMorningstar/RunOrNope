using System.Collections.Immutable;
using System.Text.Json;
using FluentAssertions;
using RunOrNope.Contracts;
using RunOrNope.Core.Evidence;
using RunOrNope.Core.Verdicts;
using Xunit;

namespace RunOrNope.UnitTests.Core;

public sealed class VerdictEngineTests
{
    [Fact]
    public void Incomplete_analysis_never_becomes_favorable()
    {
        var result = VerdictEngine.Evaluate(TestScan.IncompleteWithoutFindings());

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.RiskDisposition.Should().BeNull();
    }

    [Fact]
    public void Incomplete_analysis_with_weak_findings_never_becomes_favorable()
    {
        var scan = TestScan.WithEntropyHeuristics(1) with
        {
            AnalysisStatus = AnalysisStatus.Incomplete,
            Completeness = ArtifactCompleteness.Malformed,
        };

        VerdictEngine.Evaluate(scan).RiskDisposition.Should().BeNull();
    }

    [Fact]
    public void Correlated_entropy_findings_cannot_create_high_risk()
    {
        var result = VerdictEngine.Evaluate(TestScan.WithEntropyHeuristics(20));

        result.RiskDisposition.Should().NotBe(RiskDisposition.HighRisk);
        result.Contributions.Should().ContainSingle();
        result.Contributions[0].AppliedScore.Should().BeLessThanOrEqualTo(result.Contributions[0].FamilyCap);
    }

    [Fact]
    public void High_risk_requires_strong_application_linked_implementation()
    {
        var result = VerdictEngine.Evaluate(TestScan.WithIndependentLibraryFindings());

        result.RiskDisposition.Should().Be(RiskDisposition.CautionWarranted);
    }

    [Fact]
    public void Strong_application_implementation_can_create_high_risk()
    {
        var result = VerdictEngine.Evaluate(TestScan.WithStrongApplicationImplementation());

        result.RiskDisposition.Should().Be(RiskDisposition.HighRisk);
    }

    [Fact]
    public void Countervailing_trust_facts_do_not_subtract_behavioral_score()
    {
        var scan = TestScan.WithStrongApplicationImplementation();
        var trusted = scan with { CountervailingFacts = ["Trusted Authenticode signature"] };

        VerdictEngine.Evaluate(trusted).TotalScore.Should().Be(VerdictEngine.Evaluate(scan).TotalScore);
    }

    [Fact]
    public void Contract_json_is_deterministic_and_round_trips()
    {
        var scan = TestScan.WithStrongApplicationImplementation();

        var first = ScanContractJson.Serialize(scan);
        var second = ScanContractJson.Serialize(scan);

        first.Should().Be(second);
        ScanContractJson.Deserialize(first).Should().BeEquivalentTo(scan);
    }

    [Fact]
    public void Contract_json_matches_the_v1_golden_shape()
    {
        var json = ScanContractJson.Serialize(TestScan.IncompleteWithoutFindings());

        json.Should().Be(
            "{\"sampleName\":\"sample.exe\",\"analysisStatus\":\"incomplete\",\"completeness\":\"truncated-by-policy\",\"artifacts\":[],\"observations\":[],\"findings\":[],\"countervailingFacts\":[]}");
    }

    [Fact]
    public void Contract_json_rejects_unknown_enum_values()
    {
        var json = ScanContractJson.Serialize(TestScan.WithStrongApplicationImplementation())
            .Replace("\"complete\"", "\"future-status\"", StringComparison.Ordinal);

        var act = () => ScanContractJson.Deserialize(json);

        act.Should().Throw<JsonException>();
    }

    [Fact]
    public void Contract_boundary_rejects_invalid_in_memory_enum_values()
    {
        var scan = TestScan.IncompleteWithoutFindings() with { AnalysisStatus = (AnalysisStatus)999 };

        var act = () => ScanContractJson.Serialize(scan);

        act.Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Contract_json_rejects_unknown_members()
    {
        var json = ScanContractJson.Serialize(TestScan.IncompleteWithoutFindings())
            .Replace("\"sampleName\":", "\"unexpected\":true,\"sampleName\":", StringComparison.Ordinal);

        var act = () => ScanContractJson.Deserialize(json);

        act.Should().Throw<JsonException>();
    }

    [Theory]
    [InlineData("\u202E")]
    [InlineData("\u2066")]
    public void Contract_json_rejects_bidi_controls(string control)
    {
        var scan = TestScan.WithStrongApplicationImplementation() with { SampleName = $"safe{control}exe" };

        var act = () => ScanContractJson.Serialize(scan);

        act.Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Contract_json_rejects_oversized_collections()
    {
        var findings = Enumerable.Repeat(TestScan.Finding(RiskFamily.NetworkCommunication), ContractLimits.MaxFindings + 1)
            .ToImmutableArray();
        var scan = TestScan.Complete(findings);

        var act = () => ScanContractJson.Serialize(scan);

        act.Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Contract_json_rejects_excessive_strings()
    {
        var scan = TestScan.WithStrongApplicationImplementation() with
        {
            SampleName = new string('x', ContractLimits.MaxStringLength + 1),
        };

        var act = () => ScanContractJson.Serialize(scan);

        act.Should().Throw<ContractValidationException>();
    }
}

internal static class TestScan
{
    public static ScanResult IncompleteWithoutFindings() =>
        new("sample.exe", AnalysisStatus.Incomplete, ArtifactCompleteness.TruncatedByPolicy, [], [], [], []);

    public static ScanResult WithEntropyHeuristics(int count) =>
        Complete(Enumerable.Range(0, count)
            .Select(_ => Finding(RiskFamily.Obfuscation, EvidenceStatus.Heuristic, EvidenceConfidence.Low, Severity.Low))
            .ToImmutableArray());

    public static ScanResult WithIndependentLibraryFindings() =>
        Complete(
        [
            Finding(RiskFamily.CredentialAccess, EvidenceStatus.LinkedImplementation, EvidenceConfidence.High, Severity.Critical, ApplicationLinkage.Dependency),
            Finding(RiskFamily.Persistence, EvidenceStatus.LinkedImplementation, EvidenceConfidence.High, Severity.High, ApplicationLinkage.Dependency),
        ]);

    public static ScanResult WithStrongApplicationImplementation() =>
        Complete(
        [
            Finding(RiskFamily.CredentialAccess, EvidenceStatus.ConfirmedStaticImplementation, EvidenceConfidence.High, Severity.Critical),
            Finding(RiskFamily.DataExfiltration, EvidenceStatus.LinkedImplementation, EvidenceConfidence.High, Severity.High),
        ]);

    public static ScanResult Complete(ImmutableArray<CapabilityFinding> findings) =>
        new("sample.exe", AnalysisStatus.Complete, ArtifactCompleteness.Complete, [], [], findings, []);

    public static CapabilityFinding Finding(
        RiskFamily family,
        EvidenceStatus status = EvidenceStatus.Heuristic,
        EvidenceConfidence confidence = EvidenceConfidence.Low,
        Severity severity = Severity.Low,
        ApplicationLinkage linkage = ApplicationLinkage.Application) =>
        new(
            $"{family} evidence",
            "Potential impact",
            family,
            status,
            ParserConfidence.High,
            confidence,
            severity,
            linkage,
            Reachability.Linked,
            [],
            [],
            [],
            RecommendedAction.ReviewProvenance);
}
