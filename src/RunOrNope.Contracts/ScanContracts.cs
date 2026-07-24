using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RunOrNope.Contracts;

public enum ScanMode { Quick, Deep }
public enum EvidenceStatus { ConfirmedStaticImplementation, StrongStructuralEvidence, LinkedImplementation, ApiOrLibraryPresenceOnly, Heuristic, Unresolved }
public enum ParserConfidence { Unknown, Low, Medium, High }
public enum EvidenceConfidence { Unknown, Low, Medium, High }
public enum Severity { Informational, Low, Medium, High, Critical }
public enum AnalysisStatus { Complete, Incomplete, UnsupportedOrInvalidRootFormat, IsolationUnavailable }
public enum ArtifactCompleteness { Complete, TruncatedByPolicy, Unsupported, Encrypted, Malformed, Unavailable }
public enum ApplicationLinkage { Application, Dependency, InstallerStub, Unknown }
public enum Reachability { Confirmed, Linked, Referenced, Unknown }
public enum RecommendedAction { ReviewProvenance, ExerciseCaution, DoNotRunAndEscalate }
public enum RiskDisposition { FewMaterialStaticConcerns, CautionWarranted, HighRisk }
public enum RiskFamily
{
    NetworkCommunication, DataTransfer, CredentialAccess, DiscordTargeting, WalletTargeting,
    ProcessExecution, Persistence, PrivilegeElevation, ProcessManipulation, Surveillance,
    FilesystemDiscovery, DataExfiltration, DefenseEvasion, DestructiveBehavior,
    EmbeddedPayloads, Obfuscation, ContextualAnomaly
}

public sealed record ScanRequest(string Path, ScanMode Mode);

public sealed record SourceLocation(string ArtifactId, long? Offset, string? Region);

public sealed record ArtifactNode(
    string Id,
    string Name,
    string Sha256,
    long Size,
    ArtifactCompleteness Completeness,
    ImmutableArray<string> ParentIds);

public sealed record Observation(
    string Id,
    string Kind,
    string Description,
    ParserConfidence ParserConfidence,
    SourceLocation Source);

public sealed record CapabilityFinding(
    string Title,
    string PotentialImpact,
    RiskFamily Family,
    EvidenceStatus EvidenceStatus,
    ParserConfidence ParserConfidence,
    EvidenceConfidence EvidenceConfidence,
    Severity Severity,
    ApplicationLinkage ApplicationLinkage,
    Reachability Reachability,
    ImmutableArray<string> ObservationIds,
    ImmutableArray<string> BenignExplanations,
    ImmutableArray<string> Limitations,
    RecommendedAction RecommendedAction);

public sealed record ScanResult(
    string SampleName,
    AnalysisStatus AnalysisStatus,
    ArtifactCompleteness Completeness,
    ImmutableArray<ArtifactNode> Artifacts,
    ImmutableArray<Observation> Observations,
    ImmutableArray<CapabilityFinding> Findings,
    ImmutableArray<string> CountervailingFacts);

public static class ContractLimits
{
    public const int MaxStringLength = 16_384;
    public const int MaxArtifacts = 4_096;
    public const int MaxObservations = 65_536;
    public const int MaxFindings = 4_096;
    public const int MaxNestedStrings = 4_096;
    public const int MaxJsonBytes = 32 * 1024 * 1024;
}

public sealed class ContractValidationException(string message) : Exception(message);

public static class ScanContractJson
{
    private static readonly JsonSerializerOptions Options = CreateOptions();

    public static string Serialize(ScanResult result)
    {
        ContractValidator.Validate(result);
        return JsonSerializer.Serialize(result, Options);
    }

    public static ScanResult Deserialize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        if (System.Text.Encoding.UTF8.GetByteCount(json) > ContractLimits.MaxJsonBytes)
        {
            throw new ContractValidationException("JSON payload exceeds the maximum size.");
        }

        var result = JsonSerializer.Deserialize<ScanResult>(json, Options)
            ?? throw new JsonException("A scan result is required.");
        ContractValidator.Validate(result);
        return result;
    }

    private static JsonSerializerOptions CreateOptions()
    {
        var options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            WriteIndented = false,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        };
        options.Converters.Add(new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower, allowIntegerValues: false));
        return options;
    }
}

internal static class ContractValidator
{
    public static void Validate(ScanResult result)
    {
        ValidateEnum(result.AnalysisStatus, nameof(result.AnalysisStatus));
        ValidateEnum(result.Completeness, nameof(result.Completeness));
        ValidateString(result.SampleName, nameof(result.SampleName));
        ValidateCount(result.Artifacts.Length, ContractLimits.MaxArtifacts, nameof(result.Artifacts));
        ValidateCount(result.Observations.Length, ContractLimits.MaxObservations, nameof(result.Observations));
        ValidateCount(result.Findings.Length, ContractLimits.MaxFindings, nameof(result.Findings));
        ValidateStrings(result.CountervailingFacts, nameof(result.CountervailingFacts));

        foreach (var artifact in result.Artifacts)
        {
            ValidateEnum(artifact.Completeness, "artifact.completeness");
            ValidateString(artifact.Id, "artifact.id");
            ValidateString(artifact.Name, "artifact.name");
            ValidateString(artifact.Sha256, "artifact.sha256");
            ValidateStrings(artifact.ParentIds, "artifact.parentIds");
        }

        foreach (var observation in result.Observations)
        {
            ValidateEnum(observation.ParserConfidence, "observation.parserConfidence");
            ValidateString(observation.Id, "observation.id");
            ValidateString(observation.Kind, "observation.kind");
            ValidateString(observation.Description, "observation.description");
            ValidateString(observation.Source.ArtifactId, "observation.source.artifactId");
            if (observation.Source.Region is { } region) ValidateString(region, "observation.source.region");
        }

        foreach (var finding in result.Findings)
        {
            ValidateEnum(finding.Family, "finding.family");
            ValidateEnum(finding.EvidenceStatus, "finding.evidenceStatus");
            ValidateEnum(finding.ParserConfidence, "finding.parserConfidence");
            ValidateEnum(finding.EvidenceConfidence, "finding.evidenceConfidence");
            ValidateEnum(finding.Severity, "finding.severity");
            ValidateEnum(finding.ApplicationLinkage, "finding.applicationLinkage");
            ValidateEnum(finding.Reachability, "finding.reachability");
            ValidateEnum(finding.RecommendedAction, "finding.recommendedAction");
            ValidateString(finding.Title, "finding.title");
            ValidateString(finding.PotentialImpact, "finding.potentialImpact");
            ValidateStrings(finding.ObservationIds, "finding.observationIds");
            ValidateStrings(finding.BenignExplanations, "finding.benignExplanations");
            ValidateStrings(finding.Limitations, "finding.limitations");
        }
    }

    private static void ValidateStrings(ImmutableArray<string> values, string name)
    {
        ValidateCount(values.Length, ContractLimits.MaxNestedStrings, name);
        foreach (var value in values) ValidateString(value, name);
    }

    private static void ValidateCount(int count, int maximum, string name)
    {
        if (count > maximum) throw new ContractValidationException($"{name} exceeds its maximum count.");
    }

    private static void ValidateString(string value, string name)
    {
        if (value is null) throw new ContractValidationException($"{name} cannot be null.");
        if (value.Length > ContractLimits.MaxStringLength)
            throw new ContractValidationException($"{name} exceeds its maximum length.");
        foreach (var character in value)
        {
            if (character is '\u202A' or '\u202B' or '\u202C' or '\u202D' or '\u202E'
                or '\u2066' or '\u2067' or '\u2068' or '\u2069')
                throw new ContractValidationException($"{name} contains a bidirectional control.");
        }
    }

    private static void ValidateEnum<T>(T value, string name) where T : struct, Enum
    {
        if (!Enum.IsDefined(value)) throw new ContractValidationException($"{name} is invalid.");
    }
}
