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

    private static string Decode(byte[] bytes) => StrictUtf8.GetString(bytes);
}
