using System.Text;
using AwesomeAssertions;
using RunOrNope.Contracts;
using RunOrNope.Reporting;
using RunOrNope.Rules;
using Xunit;

namespace RunOrNope.UnitTests.Reporting;

public sealed class HtmlReportWriterTests
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    [Fact]
    public void Write_EncodesHostileTextWithoutCreatingActiveMarkup()
    {
        const string hostile = """</td><script>alert(1)</script><img src=x onerror="alert(2)">&""";

        var html = Decode(HtmlReportWriter.Write(ReportTestData.Complete(hostile)));

        html.Should().Contain("&lt;script&gt;alert(1)&lt;/script&gt;");
        html.Contains("<script", StringComparison.OrdinalIgnoreCase).Should().BeFalse();
        html.Contains("<img", StringComparison.OrdinalIgnoreCase).Should().BeFalse();
        html.Should().Contain("onerror=&quot;alert(2)&quot;");
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("file:///C:/secret.txt")]
    [InlineData(@"\\server\share\secret")]
    [InlineData("\" autofocus onfocus=\"alert(1)")]
    public void Write_RendersUriAndAttributePayloadsAsInertText(string hostile)
    {
        var html = Decode(HtmlReportWriter.Write(ReportTestData.Complete(hostile)));

        html.Should().Contain(System.Net.WebUtility.HtmlEncode(hostile));
        html.Contains("href=", StringComparison.OrdinalIgnoreCase).Should().BeFalse();
        html.Contains("src=", StringComparison.OrdinalIgnoreCase).Should().BeFalse();
    }

    [Fact]
    public void Write_UsesRestrictiveCspAndContainsNoActiveResourceElements()
    {
        var html = Decode(HtmlReportWriter.Write(ReportTestData.Complete()));

        html.Should().Contain("default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none';");
        html.Should().Contain("object-src 'none'; media-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none';");
        foreach (var element in new[] { "<script", "<iframe", "<object", "<embed", "<base", "<form", "<img", "<a " })
            html.Contains(element, StringComparison.OrdinalIgnoreCase).Should().BeFalse();
        html.Should().Contain(CapabilityRuleEngine.RulesVersion);
    }

    [Theory]
    [InlineData(@"..\..\CON.txt", "CON_.txt.runornope.html")]
    [InlineData(@"folder/name?.exe. ", "name_.exe.runornope.html")]
    [InlineData("", "sample.runornope.html")]
    public void SuggestFileName_ReturnsSafeLeafName(string input, string expected)
    {
        HtmlReportWriter.SuggestFileName(input).Should().Be(expected);
    }

    [Fact]
    public void SuggestFileName_CapsUnicodeScalarsWithoutSplittingSurrogates()
    {
        var input = new string('a', 119) + "😀tail.exe";

        var name = HtmlReportWriter.SuggestFileName(input);

        name.Should().Be(new string('a', 119) + "😀.runornope.html");
    }

    [Fact]
    public void Write_IsDeterministicValidUtf8WithoutBom()
    {
        var result = ReportTestData.WithSampleName("emoji-😀.exe");

        var first = HtmlReportWriter.Write(result);
        var second = HtmlReportWriter.Write(result);

        first.Should().Equal(second);
        first.Take(3).SequenceEqual(new byte[] { 0xEF, 0xBB, 0xBF }).Should().BeFalse();
        Decode(first).Should().Contain(System.Net.WebUtility.HtmlEncode("emoji-😀.exe"));
    }

    [Fact]
    public void Write_RejectsBidiAndMalformedUnicode()
    {
        var bidi = ReportTestData.WithSampleName("safe\u202Eexe");
        var malformed = ReportTestData.WithSampleName("bad\uD800");

        ((Action)(() => HtmlReportWriter.Write(bidi))).Should().Throw<ContractValidationException>();
        ((Action)(() => HtmlReportWriter.Write(malformed))).Should().Throw<ContractValidationException>();
    }

    [Fact]
    public void Write_DistinguishesPresenceOnlyFindingFromStructuralFinding()
    {
        var template = ReportTestData.Complete();
        var presence = template.Findings[0] with
        {
            Title = "Checks for a debugger",
            Family = RiskFamily.DefenseEvasion,
            Severity = Severity.Informational,
            EvidenceStatus = EvidenceStatus.ApiOrLibraryPresenceOnly,
            EvidenceConfidence = EvidenceConfidence.Low,
            Reachability = Reachability.Referenced,
            ApplicationLinkage = ApplicationLinkage.Dependency,
            RecommendedAction = RecommendedAction.ReviewProvenance,
            ObservationIds = ["obs-presence"],
        };
        var structural = template.Findings[0] with
        {
            Title = "Injects code into another process",
            Family = RiskFamily.ProcessManipulation,
            Severity = Severity.High,
            EvidenceStatus = EvidenceStatus.StrongStructuralEvidence,
            EvidenceConfidence = EvidenceConfidence.High,
            Reachability = Reachability.Linked,
            ApplicationLinkage = ApplicationLinkage.Application,
            RecommendedAction = RecommendedAction.ExerciseCaution,
            ObservationIds = ["obs-structural"],
        };
        var dependency = template.Artifacts[0] with
        {
            Id = "dependency",
            Name = "library.dll",
            ApplicationLinkage = ApplicationLinkage.Dependency,
        };
        var application = template.Artifacts[0] with
        {
            Id = "application",
            ApplicationLinkage = ApplicationLinkage.Application,
        };
        var presenceObservation = template.Observations[0] with
        {
            Id = "obs-presence",
            Source = new SourceLocation("dependency", 1, "imports"),
        };
        var structuralObservation = template.Observations[0] with
        {
            Id = "obs-structural",
            Source = new SourceLocation("application", 2, "imports"),
        };
        var result = template with
        {
            Artifacts = [dependency, application],
            Observations = [presenceObservation, structuralObservation],
            Findings = [presence, structural],
        };

        var html = Decode(HtmlReportWriter.Write(result));

        html.Should().Contain("Checks for a debugger")
            .And.Contain("Informational")
            .And.Contain("ApiOrLibraryPresenceOnly")
            .And.Contain("ReviewProvenance")
            .And.Contain("Injects code into another process")
            .And.Contain("High")
            .And.Contain("StrongStructuralEvidence")
            .And.Contain("ExerciseCaution");
        html.Should().Contain("DefenseEvasion").And.Contain("ProcessManipulation");
        html.Should().Contain("Dependency").And.Contain("Application");
        html.Should().Contain("Referenced").And.Contain("Linked");
    }

    [Fact]
    public void Write_RendersObservationOffsetAndRegion()
    {
        var result = ReportTestData.Complete() with
        {
            Observations =
            [
                ReportTestData.Complete().Observations[0] with
                {
                    Source = new SourceLocation("root", 4660, "import table")
                }
            ]
        };

        var html = Decode(HtmlReportWriter.Write(result));

        html.Should().Contain("Offset: 4660").And.Contain("Region: import table");
    }

    private static string Decode(byte[] bytes) => StrictUtf8.GetString(bytes);
}
