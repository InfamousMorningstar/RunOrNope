using RunOrNope.Reporting;
using RunOrNope.Contracts;
using System.IO;

namespace RunOrNope.App.Services;

public sealed class ReportExportService : IReportExportService
{
    public async Task ExportAsync(
        ScanResult result,
        ReportDestination destination,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentException.ThrowIfNullOrWhiteSpace(destination.Path);
        var options = new ReportOptions(destination.EvidenceMode);
        var bytes = destination.Format switch
        {
            ReportFormat.Html => HtmlReportWriter.Write(result, options),
            ReportFormat.Json => JsonReportWriter.Write(result, options),
            _ => throw new ArgumentOutOfRangeException(nameof(destination)),
        };
        await using var stream = new FileStream(
            destination.Path, FileMode.Create, FileAccess.Write, FileShare.None,
            bufferSize: 64 * 1024, useAsync: true);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }
}
