using System.Globalization;
using RunOrNope.Contracts;

namespace RunOrNope.App.ViewModels;

public sealed record CapabilityCardViewModel(
    string Title,
    string PotentialImpact,
    string ContextLabel,
    string Severity,
    string EvidenceStatus,
    string EvidenceConfidence,
    string ParserConfidence,
    string Reachability,
    string ApplicationLinkage,
    string Family,
    string RecommendedAction,
    IReadOnlyList<string> Sources,
    IReadOnlyList<string> BenignExplanations,
    IReadOnlyList<string> Limitations)
{
    public static CapabilityCardViewModel From(ScanResult result, CapabilityFinding finding)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(finding);
        ContractValidator.Validate(result);

        var observations = result.Observations.ToDictionary(item => item.Id, StringComparer.Ordinal);
        var artifacts = result.Artifacts.ToDictionary(item => item.Id, StringComparer.Ordinal);
        var sources = finding.ObservationIds.Select(id =>
        {
            var observation = observations[id];
            var artifact = artifacts[observation.Source.ArtifactId];
            var offset = observation.Source.Offset?.ToString(CultureInfo.InvariantCulture) ?? "Not reported";
            var region = observation.Source.Region ?? "Not reported";
            return $"{id} · {artifact.Name} · offset {offset} · {region}";
        }).ToArray();

        var context = finding.EvidenceStatus switch
        {
            RunOrNope.Contracts.EvidenceStatus.ApiOrLibraryPresenceOnly => "Context — API or library presence only",
            RunOrNope.Contracts.EvidenceStatus.StrongStructuralEvidence when
                finding.Severity is RunOrNope.Contracts.Severity.High or RunOrNope.Contracts.Severity.Critical =>
                "Caution — strong structural evidence",
            RunOrNope.Contracts.EvidenceStatus.ConfirmedStaticImplementation => "Confirmed static implementation",
            _ => "Static evidence — review context",
        };

        return new(
            finding.Title,
            finding.PotentialImpact,
            context,
            finding.Severity.ToString(),
            finding.EvidenceStatus.ToString(),
            finding.EvidenceConfidence.ToString(),
            finding.ParserConfidence.ToString(),
            finding.Reachability.ToString(),
            finding.ApplicationLinkage.ToString(),
            finding.Family.ToString(),
            finding.RecommendedAction.ToString(),
            sources,
            finding.BenignExplanations,
            finding.Limitations);
    }
}
