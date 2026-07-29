using AwesomeAssertions;
using RunOrNope.App.Services;
using RunOrNope.Reporting;
using Xunit;

namespace RunOrNope.UnitTests.App;

public sealed class ReportExportServiceTests
{
    [Theory]
    [InlineData(ReportFormat.Html, "<!doctype html>")]
    [InlineData(ReportFormat.Json, "\"schemaVersion\":\"runornope-report-1\"")]
    public async Task ExportAsync_WritesSelectedFormatToConfirmedPath(
        ReportFormat format, string marker)
    {
        var path = Path.Combine(Path.GetTempPath(), $"ronp-export-{Guid.NewGuid():N}");
        try
        {
            await new ReportExportService().ExportAsync(
                AppTestData.ScanResult(),
                new ReportDestination(path, format, ReportEvidenceMode.Redacted),
                TestContext.Current.CancellationToken);

            (await File.ReadAllTextAsync(path, TestContext.Current.CancellationToken))
                .Should().Contain(marker);
        }
        finally
        {
            try { File.Delete(path); } catch (IOException) { }
        }
    }
}
