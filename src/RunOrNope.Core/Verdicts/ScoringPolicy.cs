using RunOrNope.Contracts;

namespace RunOrNope.Core.Verdicts;

public static class ScoringPolicy
{
    public const string ScoringVersion = "1.0.0";
    public const string ThresholdVersion = "1.0.0";
    public const int FamilyCap = 40;
    public const int CautionThreshold = 15;
    public const int HighRiskThreshold = 60;

    public static int Score(CapabilityFinding finding)
    {
        var severity = finding.Severity switch
        {
            Severity.Informational => 0,
            Severity.Low => 4,
            Severity.Medium => 10,
            Severity.High => 18,
            Severity.Critical => 24,
            _ => 0,
        };
        var evidence = finding.EvidenceStatus switch
        {
            EvidenceStatus.ConfirmedStaticImplementation => 16,
            EvidenceStatus.StrongStructuralEvidence => 12,
            EvidenceStatus.LinkedImplementation => 10,
            EvidenceStatus.ApiOrLibraryPresenceOnly => 3,
            EvidenceStatus.Heuristic => 2,
            _ => 0,
        };
        var confidence = finding.EvidenceConfidence switch
        {
            EvidenceConfidence.High => 6,
            EvidenceConfidence.Medium => 3,
            EvidenceConfidence.Low => 1,
            _ => 0,
        };
        return severity + evidence + confidence;
    }

    public static bool IsStrongApplicationImplementation(CapabilityFinding finding) =>
        finding.ApplicationLinkage == ApplicationLinkage.Application
        && finding.EvidenceConfidence == EvidenceConfidence.High
        && finding.EvidenceStatus is EvidenceStatus.ConfirmedStaticImplementation
            or EvidenceStatus.StrongStructuralEvidence
            or EvidenceStatus.LinkedImplementation;
}
