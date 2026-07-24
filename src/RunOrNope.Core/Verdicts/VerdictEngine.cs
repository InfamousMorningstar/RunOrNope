using System.Collections.Immutable;
using RunOrNope.Contracts;

namespace RunOrNope.Core.Verdicts;

public sealed record VerdictContribution(
    RiskFamily Family,
    int RawScore,
    int AppliedScore,
    int FamilyCap);

public sealed record VerdictResult(
    AnalysisStatus AnalysisStatus,
    RiskDisposition? RiskDisposition,
    int TotalScore,
    ImmutableArray<VerdictContribution> Contributions,
    ImmutableArray<string> CountervailingFacts,
    string ScoringVersion,
    string ThresholdVersion);

public static class VerdictEngine
{
    public static VerdictResult Evaluate(ScanResult scan)
    {
        ArgumentNullException.ThrowIfNull(scan);
        var contributions = scan.Findings
            .GroupBy(finding => finding.Family)
            .OrderBy(group => group.Key)
            .Select(group =>
            {
                var raw = group.Sum(ScoringPolicy.Score);
                return new VerdictContribution(group.Key, raw, Math.Min(raw, ScoringPolicy.FamilyCap), ScoringPolicy.FamilyCap);
            })
            .ToImmutableArray();
        var total = contributions.Sum(item => item.AppliedScore);

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

    private static RiskDisposition DetermineDisposition(ScanResult scan, int total)
    {
        var strongFamilies = scan.Findings
            .Where(ScoringPolicy.IsStrongApplicationImplementation)
            .Select(finding => finding.Family)
            .Distinct()
            .Count();
        var hasConfirmedCritical = scan.Findings.Any(finding =>
            ScoringPolicy.IsStrongApplicationImplementation(finding)
            && finding.EvidenceStatus == EvidenceStatus.ConfirmedStaticImplementation
            && finding.Severity == Severity.Critical);

        if (total >= ScoringPolicy.HighRiskThreshold && strongFamilies >= 2 && hasConfirmedCritical)
            return RiskDisposition.HighRisk;
        return total >= ScoringPolicy.CautionThreshold
            ? RiskDisposition.CautionWarranted
            : RiskDisposition.FewMaterialStaticConcerns;
    }
}
