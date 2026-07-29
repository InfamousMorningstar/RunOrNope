using System.Collections.Immutable;
using System.Text.RegularExpressions;
using RunOrNope.Contracts;

namespace RunOrNope.Reporting;

internal static partial class RedactionPolicy
{
    internal const string FullEvidenceWarning =
        "Full evidence may contain credentials, personal data, or sensitive paths.";

    internal static ScanResult Project(ScanResult result, ReportEvidenceMode mode)
    {
        if (mode == ReportEvidenceMode.Full) return result;

        return result with
        {
            SampleName = Redact(result.SampleName),
            Artifacts = result.Artifacts.Select(Project).ToImmutableArray(),
            Observations = result.Observations.Select(Project).ToImmutableArray(),
            Findings = result.Findings.Select(Project).ToImmutableArray(),
            CountervailingFacts = Project(result.CountervailingFacts),
        };
    }

    internal static string? Warning(ReportEvidenceMode mode) =>
        mode == ReportEvidenceMode.Full ? FullEvidenceWarning : null;

    private static ArtifactNode Project(ArtifactNode artifact) => artifact with
    {
        Name = Redact(artifact.Name),
    };

    private static Observation Project(Observation observation) => observation with
    {
        Description = Redact(observation.Description),
        Source = observation.Source with
        {
            Region = observation.Source.Region is null ? null : Redact(observation.Source.Region),
        },
    };

    private static CapabilityFinding Project(CapabilityFinding finding) => finding with
    {
        Title = Redact(finding.Title),
        PotentialImpact = Redact(finding.PotentialImpact),
        BenignExplanations = Project(finding.BenignExplanations),
        Limitations = Project(finding.Limitations),
    };

    private static ImmutableArray<string> Project(ImmutableArray<string> values) =>
        values.Select(Redact).ToImmutableArray();

    private static string Redact(string value)
    {
        var redacted = UriCredentials().Replace(value, "${scheme}${user}[REDACTED]@");
        redacted = Authorization().Replace(redacted, "${prefix}[REDACTED]");
        redacted = NamedValue().Replace(redacted, "${prefix}[REDACTED]");
        return PrivateKey().Replace(redacted, "${begin}\n[REDACTED]\n${end}");
    }

    [GeneratedRegex(@"(?<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?<user>[^/\s:@]+:)[^@/\s]+@", RegexOptions.CultureInvariant)]
    private static partial Regex UriCredentials();

    [GeneratedRegex(@"(?<prefix>Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s,;]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex Authorization();

    [GeneratedRegex(@"(?<prefix>(?:^|[?&;\s])(?:token|access_token|api_key|apikey|secret|password|passwd)\s*(?:=|:)\s*)[^&;\s]+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex NamedValue();

    [GeneratedRegex(@"(?<begin>-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----)[\s\S]*?(?<end>-----END (?:[A-Z ]+ )?PRIVATE KEY-----)", RegexOptions.CultureInvariant)]
    private static partial Regex PrivateKey();
}
