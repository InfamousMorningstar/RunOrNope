using System.Text;
using AwesomeAssertions;
using RunOrNope.Reporting;
using Xunit;

namespace RunOrNope.UnitTests.Reporting;

public sealed class RedactionPolicyTests
{
    [Theory]
    [InlineData("https://alice:hunter2@example.test/path", "hunter2")]
    [InlineData("https://example.test/?access_token=abc123&safe=yes", "abc123")]
    [InlineData("Authorization: Bearer ey.secret.token", "ey.secret.token")]
    [InlineData("password: correct-horse-battery", "correct-horse-battery")]
    public void DefaultMode_RedactsCredentialValuesInBothFormats(string evidence, string secret)
    {
        var result = ReportTestData.Complete(evidence);

        var json = Encoding.UTF8.GetString(JsonReportWriter.Write(result));
        var html = Encoding.UTF8.GetString(HtmlReportWriter.Write(result));

        json.Should().NotContain(secret).And.Contain("[REDACTED]");
        html.Should().NotContain(secret).And.Contain("[REDACTED]");
        json.Should().Contain(ReportTestData.Sha);
    }

    [Fact]
    public void FullMode_PreservesEvidenceAndDisplaysPrivacyWarning()
    {
        const string evidence = "api_key=super-secret";
        var options = new ReportOptions(ReportEvidenceMode.Full);

        var json = Encoding.UTF8.GetString(JsonReportWriter.Write(ReportTestData.Complete(evidence), options));
        var html = Encoding.UTF8.GetString(HtmlReportWriter.Write(ReportTestData.Complete(evidence), options));

        json.Should().Contain(evidence).And.Contain("Full evidence may contain credentials");
        html.Should().Contain(evidence).And.Contain("Full evidence may contain credentials");
    }
}
