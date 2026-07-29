using System.Text.Json;
using System.Text.Json.Serialization;
using RunOrNope.Contracts;
using RunOrNope.Core.Verdicts;
using RunOrNope.Rules;

namespace RunOrNope.Reporting;

public static class JsonReportWriter
{
    internal const string SchemaVersion = "runornope-report-1";
    private static readonly JsonSerializerOptions JsonOptions = CreateOptions();

    public static byte[] Write(ScanResult result, ReportOptions? options = null)
    {
        ContractValidator.Validate(result);
        var envelope = CreateEnvelope(result, options ?? ReportOptions.Default);
        var bytes = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonOptions);
        if (bytes.Length > ContractLimits.MaxJsonBytes)
            throw new ContractValidationException("Report JSON exceeds the maximum size.");
        return bytes;
    }

    internal static ReportEnvelope CreateEnvelope(ScanResult result, ReportOptions options)
    {
        if (!Enum.IsDefined(options.EvidenceMode))
            throw new ArgumentOutOfRangeException(nameof(options), "Evidence mode is invalid.");

        var verdict = VerdictEngine.Evaluate(result);
        var action = result.Findings.IsDefaultOrEmpty
            ? RecommendedAction.ReviewProvenance
            : result.Findings.Max(static finding => finding.RecommendedAction);
        return new(
            SchemaVersion,
            new(
                CapabilityRuleEngine.RulesVersion,
                verdict.ScoringVersion,
                verdict.ThresholdVersion,
                new(
                    ContractLimits.MaxStringLength,
                    ContractLimits.MaxArtifacts,
                    ContractLimits.MaxObservations,
                    ContractLimits.MaxFindings,
                    ContractLimits.MaxNestedStrings,
                    ContractLimits.MaxJsonBytes)),
            new(options.EvidenceMode, RedactionPolicy.Warning(options.EvidenceMode)),
            new(verdict.AnalysisStatus, verdict.RiskDisposition, action, verdict.TotalScore, verdict.Contributions),
            RedactionPolicy.Project(result, options.EvidenceMode));
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower, allowIntegerValues: false));
        return options;
    }
}
