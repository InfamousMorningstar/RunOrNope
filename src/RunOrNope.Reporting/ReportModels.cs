using RunOrNope.Contracts;
using RunOrNope.Core.Verdicts;

namespace RunOrNope.Reporting;

public enum ReportEvidenceMode { Redacted, Full }

public sealed record ReportOptions(ReportEvidenceMode EvidenceMode)
{
    public static ReportOptions Default { get; } = new(ReportEvidenceMode.Redacted);
}

internal sealed record ReportEnvelope(
    string SchemaVersion,
    ReproducibilityMetadata Reproducibility,
    PrivacyMetadata Privacy,
    ReportVerdict Verdict,
    ScanResult ScanResult);

internal sealed record ReproducibilityMetadata(
    string RulesVersion,
    string ScoringVersion,
    string ThresholdVersion,
    ContractLimitMetadata ContractLimits);

internal sealed record ContractLimitMetadata(
    int MaxStringLength,
    int MaxArtifacts,
    int MaxObservations,
    int MaxFindings,
    int MaxNestedStrings,
    int MaxJsonBytes);

internal sealed record PrivacyMetadata(ReportEvidenceMode EvidenceMode, string? Warning);

internal sealed record ReportVerdict(
    AnalysisStatus AnalysisStatus,
    RiskDisposition? RiskDisposition,
    RecommendedAction RecommendedAction,
    long Score,
    IReadOnlyList<VerdictContribution> Contributions);
