using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.Core.Verdicts;

public sealed record VerdictContribution(
    RiskFamily Family,
    long RawScore,
    long AppliedScore,
    long FamilyCap);

public sealed record VerdictResult(
    AnalysisStatus AnalysisStatus,
    RiskDisposition? RiskDisposition,
    long TotalScore,
    ImmutableArray<VerdictContribution> Contributions,
    ImmutableArray<string> CountervailingFacts,
    string ScoringVersion,
    string ThresholdVersion);

public static class VerdictEngine
{
    public static VerdictResult Evaluate(ScanResult scan)
    {
        ContractValidator.Validate(scan);
        var contributions = scan.Findings
            .GroupBy(finding => finding.Family)
            .OrderBy(group => group.Key)
            .Select(group =>
            {
                var raw = group.Aggregate(0L, static (sum, finding) => checked(sum + ScoringPolicy.Score(finding)));
                return new VerdictContribution(group.Key, raw, Math.Min(raw, ScoringPolicy.FamilyCap), ScoringPolicy.FamilyCap);
            })
            .ToImmutableArray();
        var total = contributions.Aggregate(0L, static (sum, item) => checked(sum + item.AppliedScore));

        var candidate = DetermineDisposition(scan, total);
        RiskDisposition? disposition = scan.AnalysisStatus switch
        {
            AnalysisStatus.UnsupportedOrInvalidRootFormat or AnalysisStatus.IsolationUnavailable => null,
            AnalysisStatus.Incomplete when candidate == RiskDisposition.FewMaterialStaticConcerns => null,
            _ => candidate,
        };

        return new(
            scan.AnalysisStatus,
            disposition,
            total,
            contributions,
            scan.CountervailingFacts,
            ScoringPolicy.ScoringVersion,
            ScoringPolicy.ThresholdVersion);
    }

    private static RiskDisposition DetermineDisposition(ScanResult scan, long total)
    {
        var eligible = scan.Findings
            .Where(ScoringPolicy.IsStrongApplicationImplementation)
            .ToArray();
        var strongFamilies = eligible
            .Select(finding => finding.Family)
            .Distinct()
            .Count();
        var hasConfirmedCritical = eligible.Any(finding =>
            finding.EvidenceStatus == EvidenceStatus.ConfirmedStaticImplementation
            && finding.Severity == Severity.Critical);
        var eligibleScore = eligible
            .GroupBy(finding => finding.Family)
            .Aggregate(0L, static (sum, group) =>
                checked(sum + Math.Min(
                    group.Aggregate(0L, static (familySum, finding) =>
                        checked(familySum + ScoringPolicy.Score(finding))),
                    ScoringPolicy.FamilyCap)));

        if (eligibleScore >= ScoringPolicy.HighRiskThreshold && strongFamilies >= 2 && hasConfirmedCritical)
            return RiskDisposition.HighRisk;
        return total >= ScoringPolicy.CautionThreshold
            ? RiskDisposition.CautionWarranted
            : RiskDisposition.FewMaterialStaticConcerns;
    }
}
