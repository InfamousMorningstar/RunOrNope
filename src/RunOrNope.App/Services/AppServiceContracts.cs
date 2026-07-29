using RunOrNope.Contracts;
using RunOrNope.Core.Verdicts;
using RunOrNope.Reporting;

namespace RunOrNope.App.Services;

public sealed record CompletedScan(
    ScanResult Result,
    VerdictResult Verdict,
    string Sha256,
    long Size);

public interface IScanCoordinator
{
    Task<CompletedScan> ScanAsync(
        string path, ScanMode mode, CancellationToken cancellationToken);
}

public enum ReportFormat { Html, Json }

public sealed record ReportDestination(
    string Path, ReportFormat Format, ReportEvidenceMode EvidenceMode);

public interface IReportExportService
{
    Task ExportAsync(
        ScanResult result, ReportDestination destination, CancellationToken cancellationToken);
}

public enum HashReputationStatus
{
    Found, NotFound, Unauthorized, RateLimited, ServiceUnavailable,
    InvalidResponse, Skipped, Failed
}

public sealed record HashReputationResult(
    HashReputationStatus Status,
    string Sha256,
    int Malicious,
    int Suspicious,
    int Harmless,
    int Undetected,
    DateTimeOffset? LastAnalysisUtc);

public interface IHashReputationLookup
{
    Task<HashReputationResult> LookupAsync(
        string sha256, string apiKey, CancellationToken cancellationToken);
}

public interface IUserInteraction
{
    string? ChooseSample();
    ReportDestination? ChooseReportDestination(string suggestedName, ReportFormat format);
    Task<bool> ConfirmHashLookupAsync(
        string sha256, Uri destination, CancellationToken cancellationToken);
}
