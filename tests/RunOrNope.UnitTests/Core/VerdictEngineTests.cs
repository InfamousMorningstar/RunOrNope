using System.Collections.Immutable;
using System.Text.Json;
using AwesomeAssertions;
using Json.Schema;
using RunOrNope.Contracts;
using RunOrNope.Core.Evidence;
using RunOrNope.Core.Verdicts;
using RunOrNope.UnitTests.Architecture;
using Xunit;

namespace RunOrNope.UnitTests.Core;

public sealed class VerdictEngineTests
{
    private static readonly Lazy<JsonSchema> ReportSchema = new(LoadReportSchema);
    private static readonly JsonSerializerOptions ContractShapeOptions = CreateContractShapeOptions();

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

    [Theory]
    [InlineData(Reachability.Unknown, ParserConfidence.High)]
    [InlineData(Reachability.Referenced, ParserConfidence.High)]
    [InlineData(Reachability.Linked, ParserConfidence.Unknown)]
    [InlineData(Reachability.Linked, ParserConfidence.Low)]
    public void High_risk_rejects_unreachable_or_unreliable_evidence(
        Reachability reachability,
        ParserConfidence parserConfidence)
    {
        var scan = TestScan.WithStrongApplicationImplementation();
        var weakened = scan with
        {
            Findings = scan.Findings
                .Select(finding => finding with
                {
                    Reachability = reachability,
                    ParserConfidence = parserConfidence,
                })
                .ToImmutableArray(),
        };

        VerdictEngine.Evaluate(weakened).RiskDisposition.Should().NotBe(RiskDisposition.HighRisk);
    }

    [Fact]
    public void Structural_evidence_without_implementation_cannot_enable_high_risk()
    {
        var scan = TestScan.WithStrongApplicationImplementation();
        var structural = scan with
        {
            Findings = scan.Findings
                .Select(finding => finding with { EvidenceStatus = EvidenceStatus.StrongStructuralEvidence })
                .ToImmutableArray(),
        };

        VerdictEngine.Evaluate(structural).RiskDisposition.Should().NotBe(RiskDisposition.HighRisk);
    }

    [Fact]
    public void Weak_findings_cannot_supply_high_risk_threshold_remainder()
    {
        var eligible = TestScan.Finding(
            RiskFamily.CredentialAccess,
            EvidenceStatus.LinkedImplementation,
            EvidenceConfidence.High,
            Severity.High);
        var weak = Enumerable.Range(0, 100)
            .Select(index => TestScan.Finding(
                index % 2 == 0 ? RiskFamily.Obfuscation : RiskFamily.ContextualAnomaly,
                EvidenceStatus.Heuristic,
                EvidenceConfidence.Low,
                Severity.Low));
        var scan = TestScan.Complete([eligible, .. weak]);

        VerdictEngine.Evaluate(scan).RiskDisposition.Should().NotBe(RiskDisposition.HighRisk);
    }

    [Fact]
    public void Contextual_families_never_qualify_as_high_risk_implementation()
    {
        var scan = TestScan.Complete(
        [
            TestScan.Finding(
                RiskFamily.Obfuscation,
                EvidenceStatus.ConfirmedStaticImplementation,
                EvidenceConfidence.High,
                Severity.Critical),
            TestScan.Finding(
                RiskFamily.CredentialAccess,
                EvidenceStatus.ConfirmedStaticImplementation,
                EvidenceConfidence.High,
                Severity.Critical),
        ]);

        VerdictEngine.Evaluate(scan).RiskDisposition.Should().NotBe(RiskDisposition.HighRisk);
    }

    [Fact]
    public void Family_accumulation_saturates_safely_at_the_collection_boundary()
    {
        var findings = Enumerable.Repeat(
            TestScan.Finding(
                RiskFamily.NetworkCommunication,
                EvidenceStatus.ConfirmedStaticImplementation,
                EvidenceConfidence.High,
                Severity.Critical),
            ContractLimits.MaxFindings).ToImmutableArray();

        var result = VerdictEngine.Evaluate(TestScan.Complete(findings));

        result.Contributions.Should().ContainSingle();
        result.Contributions[0].RawScore.Should().Be(188_416L);
        result.Contributions[0].AppliedScore.Should().Be(ScoringPolicy.FamilyCap);
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

    [Fact]
    public void Contract_json_rejects_aggregate_output_over_32_mib()
    {
        var large = new string('x', ContractLimits.MaxStringLength);
        var observations = Enumerable.Range(0, 1_100)
            .Select(index => new Observation(
                index.ToString(System.Globalization.CultureInfo.InvariantCulture),
                large,
                large,
                ParserConfidence.High,
                new SourceLocation("artifact", index, large)))
            .ToImmutableArray();
        var scan = TestScan.Complete([]) with
        {
            Artifacts = [TestScan.Artifact("artifact", ApplicationLinkage.Application)],
            Observations = observations,
        };

        var act = () => ScanContractJson.Serialize(scan);

        act.Should().Throw<ContractValidationException>().WithMessage("*maximum size*");
    }

    [Fact]
    public void Verdict_entry_rejects_invalid_contracts_with_controlled_exception()
    {
        var invalid = TestScan.Complete([]) with
        {
            Artifacts =
            [
                new ArtifactNode("id", "name", "not-a-hash", -1, ArtifactCompleteness.Complete, default),
            ],
        };

        var act = () => VerdictEngine.Evaluate(invalid);

        act.Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Verdict_entry_rejects_contradictory_completeness()
    {
        var invalid = TestScan.Complete([]) with { Completeness = ArtifactCompleteness.Malformed };

        var act = () => VerdictEngine.Evaluate(invalid);

        act.Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Verdict_entry_rejects_incomplete_child_of_complete_result()
    {
        var invalid = TestScan.Complete([]) with
        {
            Artifacts =
            [
                new ArtifactNode(
                    "id", "name", new string('a', 64), 0,
                    ArtifactCompleteness.Encrypted, []),
            ],
        };

        var act = () => VerdictEngine.Evaluate(invalid);

        act.Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Verdict_entry_rejects_null_nested_records_and_elements()
    {
        var nullSource = TestScan.Complete([]) with
        {
            Observations = [new Observation("o", "kind", "fact", ParserConfidence.High, null!)],
        };
        var nullFinding = TestScan.Complete([]) with { Findings = [null!] };

        FluentActions.Invoking(() => VerdictEngine.Evaluate(nullSource))
            .Should().Throw<ContractValidationException>();
        FluentActions.Invoking(() => VerdictEngine.Evaluate(nullFinding))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Verdict_entry_rejects_default_immutable_arrays()
    {
        var invalid = TestScan.Complete([]) with { Observations = default };

        FluentActions.Invoking(() => VerdictEngine.Evaluate(invalid))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Verdict_entry_rejects_null_root_with_controlled_exception()
    {
        FluentActions.Invoking(() => VerdictEngine.Evaluate(null!))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Score_contributing_finding_requires_observation_provenance()
    {
        var finding = TestScan.Finding(RiskFamily.CredentialAccess) with { ObservationIds = [] };
        var scan = TestScan.CompleteWithoutProvenance([finding]);

        FluentActions.Invoking(() => VerdictEngine.Evaluate(scan))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Finding_rejects_missing_and_duplicate_observation_ids()
    {
        var finding = TestScan.Finding(RiskFamily.CredentialAccess) with { ObservationIds = ["missing"] };
        var missing = TestScan.CompleteWithoutProvenance([finding]);
        var duplicate = TestScan.CompleteWithoutProvenance([finding]) with
        {
            Artifacts = [TestScan.Artifact("app", ApplicationLinkage.Application)],
            Observations =
            [
                TestScan.Observation("missing", "app"),
                TestScan.Observation("missing", "app"),
            ],
        };

        FluentActions.Invoking(() => VerdictEngine.Evaluate(missing))
            .Should().Throw<ContractValidationException>();
        FluentActions.Invoking(() => VerdictEngine.Evaluate(duplicate))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Observation_rejects_missing_and_duplicate_artifact_ids()
    {
        var finding = TestScan.Finding(RiskFamily.CredentialAccess) with { ObservationIds = ["o"] };
        var missing = TestScan.CompleteWithoutProvenance([finding]) with
        {
            Observations = [TestScan.Observation("o", "missing")],
        };
        var duplicate = missing with
        {
            Artifacts =
            [
                TestScan.Artifact("missing", ApplicationLinkage.Application),
                TestScan.Artifact("missing", ApplicationLinkage.Application),
            ],
        };

        FluentActions.Invoking(() => VerdictEngine.Evaluate(missing))
            .Should().Throw<ContractValidationException>();
        FluentActions.Invoking(() => VerdictEngine.Evaluate(duplicate))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Cross_artifact_linkage_cannot_support_application_finding()
    {
        var finding = TestScan.Finding(
            RiskFamily.CredentialAccess,
            EvidenceStatus.ConfirmedStaticImplementation,
            EvidenceConfidence.High,
            Severity.Critical) with { ObservationIds = ["dependency-observation"] };
        var scan = TestScan.CompleteWithoutProvenance([finding]) with
        {
            Artifacts = [TestScan.Artifact("dependency", ApplicationLinkage.Dependency)],
            Observations = [TestScan.Observation("dependency-observation", "dependency")],
        };

        FluentActions.Invoking(() => VerdictEngine.Evaluate(scan))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Finding_rejects_duplicate_citations_and_mixed_source_artifacts()
    {
        var duplicated = TestScan.Finding(RiskFamily.CredentialAccess) with { ObservationIds = ["o", "o"] };
        var duplicatedScan = TestScan.CompleteWithoutProvenance([duplicated]) with
        {
            Artifacts = [TestScan.Artifact("app", ApplicationLinkage.Application)],
            Observations = [TestScan.Observation("o", "app")],
        };
        var mixed = duplicated with { ObservationIds = ["o1", "o2"] };
        var mixedScan = TestScan.CompleteWithoutProvenance([mixed]) with
        {
            Artifacts =
            [
                TestScan.Artifact("app-1", ApplicationLinkage.Application),
                TestScan.Artifact("app-2", ApplicationLinkage.Application),
            ],
            Observations =
            [
                TestScan.Observation("o1", "app-1"),
                TestScan.Observation("o2", "app-2"),
            ],
        };

        FluentActions.Invoking(() => VerdictEngine.Evaluate(duplicatedScan))
            .Should().Throw<ContractValidationException>();
        FluentActions.Invoking(() => VerdictEngine.Evaluate(mixedScan))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Weak_cited_observation_cannot_make_finding_high_risk_eligible()
    {
        var scan = TestScan.WithStrongApplicationImplementation();
        var weakObservations = scan with
        {
            Observations = scan.Observations
                .Select(observation => observation with { ParserConfidence = ParserConfidence.Low })
                .ToImmutableArray(),
        };

        VerdictEngine.Evaluate(weakObservations).RiskDisposition.Should().NotBe(RiskDisposition.HighRisk);
    }

    [Fact]
    public void Observation_without_exact_location_cannot_make_finding_high_risk_eligible()
    {
        var scan = TestScan.WithStrongApplicationImplementation();
        var unlocated = scan with
        {
            Observations = scan.Observations
                .Select(observation => observation with
                {
                    Source = observation.Source with { Offset = null, Region = null },
                })
                .ToImmutableArray(),
        };

        VerdictEngine.Evaluate(unlocated).RiskDisposition.Should().NotBe(RiskDisposition.HighRisk);
    }

    [Fact]
    public void Runtime_and_draft_2020_12_schema_accept_the_same_valid_enum_values()
    {
        foreach (var family in Enum.GetValues<RiskFamily>())
        {
            var scan = TestScan.Complete([TestScan.Finding(family)]);
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(scan), expected: true);
        }

        var baseline = TestScan.Finding(RiskFamily.NetworkCommunication);
        foreach (var value in Enum.GetValues<EvidenceStatus>())
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(TestScan.Complete([baseline with { EvidenceStatus = value }])), true);
        foreach (var value in Enum.GetValues<ParserConfidence>())
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(TestScan.Complete([baseline with { ParserConfidence = value }])), true);
        foreach (var value in Enum.GetValues<EvidenceConfidence>())
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(TestScan.Complete([baseline with { EvidenceConfidence = value }])), true);
        foreach (var value in Enum.GetValues<Severity>())
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(TestScan.Complete([baseline with { Severity = value }])), true);
        foreach (var value in Enum.GetValues<ApplicationLinkage>())
        {
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(TestScan.Complete([baseline with { ApplicationLinkage = value }])), true);
            var artifactOnly = TestScan.Complete([]) with { Artifacts = [TestScan.Artifact("a", value)] };
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(artifactOnly), true);
        }
        foreach (var value in Enum.GetValues<Reachability>())
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(TestScan.Complete([baseline with { Reachability = value }])), true);
        foreach (var value in Enum.GetValues<RecommendedAction>())
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(TestScan.Complete([baseline with { RecommendedAction = value }])), true);

        foreach (var value in Enum.GetValues<ArtifactCompleteness>().Where(value => value != ArtifactCompleteness.Complete))
        {
            var scan = new ScanResult("sample.exe", AnalysisStatus.Incomplete, value, [], [], [], []);
            AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(scan), true);
        }

        var statusPairs = new[]
        {
            (AnalysisStatus.Complete, ArtifactCompleteness.Complete),
            (AnalysisStatus.Incomplete, ArtifactCompleteness.Malformed),
            (AnalysisStatus.UnsupportedOrInvalidRootFormat, ArtifactCompleteness.Unsupported),
            (AnalysisStatus.IsolationUnavailable, ArtifactCompleteness.Unavailable),
        };
        foreach (var (status, completeness) in statusPairs)
        {
            AssertRuntimeAndSchemaAgree(
                ScanContractJson.Serialize(new ScanResult("sample.exe", status, completeness, [], [], [], [])),
                true);
        }
    }

    [Fact]
    public void Runtime_and_schema_agree_at_string_and_collection_boundaries()
    {
        var maxString = new string('x', ContractLimits.MaxStringLength);
        var valid = ScanContractJson.Serialize(TestScan.Complete([]) with { SampleName = maxString });
        AssertRuntimeAndSchemaAgree(valid, true);

        var oversizedString = valid.Replace(maxString, $"{maxString}x", StringComparison.Ordinal);
        AssertRuntimeAndSchemaAgree(oversizedString, false);

        var repeatedFinding = TestScan.Finding(RiskFamily.NetworkCommunication) with { ObservationIds = ["shared"] };
        var findingJson = JsonSerializer.Serialize(repeatedFinding, ContractShapeOptions);
        var findingsAtLimit = string.Join(',', Enumerable.Repeat(findingJson, ContractLimits.MaxFindings));
        var baseJson = ScanContractJson.Serialize(TestScan.Complete([repeatedFinding]));
        var validCollection = baseJson.Replace(
            $"\"findings\":[{findingJson}]",
            $"\"findings\":[{findingsAtLimit}]",
            StringComparison.Ordinal);
        AssertRuntimeAndSchemaAgree(validCollection, true);
        var oversizedCollection = validCollection.Replace(
            $"\"findings\":[{findingsAtLimit}]",
            $"\"findings\":[{findingsAtLimit},{findingJson}]",
            StringComparison.Ordinal);
        AssertRuntimeAndSchemaAgree(oversizedCollection, false);
    }

    [Fact]
    public void Runtime_and_schema_count_non_bmp_text_as_unicode_scalars()
    {
        var scalar = char.ConvertFromUtf32(0x1F680);
        var atLimit = string.Concat(Enumerable.Repeat(scalar, ContractLimits.MaxStringLength));
        var scan = TestScan.Complete([]) with { SampleName = atLimit };
        AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(scan), true);

        var oversizedJson = ScanContractJson.Serialize(TestScan.Complete([]))
            .Replace("sample.exe", $"{atLimit}{scalar}", StringComparison.Ordinal);
        AssertRuntimeAndSchemaAgree(oversizedJson, false);
    }

    [Theory]
    [InlineData("\\uD800")]
    [InlineData("\\uDC00")]
    public void Runtime_and_schema_reject_malformed_surrogates(string escapedSurrogate)
    {
        var json = ScanContractJson.Serialize(TestScan.Complete([]))
            .Replace("sample.exe", escapedSurrogate, StringComparison.Ordinal);

        AssertRuntimeAndSchemaAgree(json, false);
    }

    [Fact]
    public void Runtime_rejects_malformed_in_memory_unicode_with_controlled_exception()
    {
        var malformed = TestScan.Complete([]) with { SampleName = "\uD800" };

        FluentActions.Invoking(() => ScanContractJson.Serialize(malformed))
            .Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Runtime_and_schema_agree_on_completeness_invariants_and_nullability()
    {
        var valid = ScanContractJson.Serialize(TestScan.Complete([]));
        var contradictory = valid.Replace("\"completeness\":\"complete\"", "\"completeness\":\"malformed\"", StringComparison.Ordinal);
        AssertRuntimeAndSchemaAgree(contradictory, false);

        var validObservation = new ScanResult(
            "sample.exe", AnalysisStatus.Complete, ArtifactCompleteness.Complete,
            [TestScan.Artifact("a", ApplicationLinkage.Application)],
            [new Observation("o", "kind", "fact", ParserConfidence.High, new SourceLocation("a", null, null))],
            [], []);
        AssertRuntimeAndSchemaAgree(ScanContractJson.Serialize(validObservation), true);
        var nullSource = ScanContractJson.Serialize(validObservation)
            .Replace("\"source\":{\"artifactId\":\"a\",\"offset\":null,\"region\":null}", "\"source\":null", StringComparison.Ordinal);
        AssertRuntimeAndSchemaAgree(nullSource, false);
    }

    [Theory]
    [InlineData("negative-size")]
    [InlineData("negative-offset")]
    [InlineData("invalid-hash")]
    [InlineData("unknown-family")]
    [InlineData("bidi")]
    [InlineData("unknown-member")]
    public void Runtime_and_draft_2020_12_schema_reject_the_same_invalid_payloads(string mutation)
    {
        var valid = new ScanResult(
            "sample.exe",
            AnalysisStatus.Complete,
            ArtifactCompleteness.Complete,
            [new ArtifactNode("a", "a.exe", new string('a', 64), 1, ArtifactCompleteness.Complete, [], ApplicationLinkage.Application)],
            [new Observation("o", "kind", "fact", ParserConfidence.High, new SourceLocation("a", 0, null))],
            [TestScan.Finding(RiskFamily.NetworkCommunication) with { ObservationIds = ["o"] }],
            []);
        var json = ScanContractJson.Serialize(valid);
        var invalid = mutation switch
        {
            "negative-size" => json.Replace("\"size\":1", "\"size\":-1", StringComparison.Ordinal),
            "negative-offset" => json.Replace("\"offset\":0", "\"offset\":-1", StringComparison.Ordinal),
            "invalid-hash" => json.Replace(new string('a', 64), "abcd", StringComparison.Ordinal),
            "unknown-family" => json.Replace("\"network-communication\"", "\"future-family\"", StringComparison.Ordinal),
            "bidi" => json.Replace("\"sample.exe\"", "\"sample\\u202eexe\"", StringComparison.Ordinal),
            "unknown-member" => json.Replace("\"sampleName\":", "\"extra\":true,\"sampleName\":", StringComparison.Ordinal),
            _ => throw new InvalidOperationException(),
        };

        AssertRuntimeAndSchemaAgree(invalid, expected: false);
    }

    private static void AssertRuntimeAndSchemaAgree(string json, bool expected)
    {
        var runtimeValid = true;
        try
        {
            _ = ScanContractJson.Deserialize(json);
        }
        catch (Exception exception) when (exception is JsonException or ContractValidationException)
        {
            runtimeValid = false;
        }

        var schemaValid = false;
        try
        {
            using var document = JsonDocument.Parse(json);
            schemaValid = ReportSchema.Value.Evaluate(document.RootElement).IsValid;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException)
        {
            schemaValid = false;
        }

        runtimeValid.Should().Be(expected);
        schemaValid.Should().Be(expected);
        runtimeValid.Should().Be(schemaValid);
    }

    private static JsonSchema LoadReportSchema()
    {
        var schemaPath = Path.Combine(RepositoryFiles.Root, "schemas", "runornope-report-v1.schema.json");
        return JsonSchema.FromText(
            File.ReadAllText(schemaPath),
            new BuildOptions { Dialect = Dialect.Draft202012 });
    }

    private static JsonSerializerOptions CreateContractShapeOptions()
    {
        var options = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        options.Converters.Add(
            new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower));
        return options;
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

    public static ScanResult Complete(ImmutableArray<CapabilityFinding> findings)
    {
        var referenced = findings
            .SelectMany(finding => finding.ObservationIds.Select(id => (id, finding.ApplicationLinkage)))
            .Distinct()
            .ToImmutableArray();
        var linkages = referenced.Select(item => item.ApplicationLinkage).Distinct().ToImmutableArray();
        var artifacts = linkages.Select(linkage => Artifact(ArtifactId(linkage), linkage)).ToImmutableArray();
        var observations = referenced
            .Select(item => Observation(item.id, ArtifactId(item.ApplicationLinkage)))
            .ToImmutableArray();
        return new("sample.exe", AnalysisStatus.Complete, ArtifactCompleteness.Complete, artifacts, observations, findings, []);
    }

    public static ScanResult CompleteWithoutProvenance(ImmutableArray<CapabilityFinding> findings) =>
        new("sample.exe", AnalysisStatus.Complete, ArtifactCompleteness.Complete, [], [], findings, []);

    public static ArtifactNode Artifact(string id, ApplicationLinkage linkage) =>
        new(id, $"{id}.bin", new string('a', 64), 1, ArtifactCompleteness.Complete, [], linkage);

    public static Observation Observation(string id, string artifactId) =>
        new(id, "implementation", "Parsed implementation evidence", ParserConfidence.High, new SourceLocation(artifactId, 0, "code"));

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
            [$"{family}-{linkage}"],
            [],
            [],
            RecommendedAction.ReviewProvenance);

    private static string ArtifactId(ApplicationLinkage linkage) => $"artifact-{linkage}";
}
