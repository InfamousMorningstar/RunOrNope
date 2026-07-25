using AwesomeAssertions;
using RunOrNope.Analyzers.Pe;
using Xunit;

namespace RunOrNope.UnitTests.Pe;

public sealed class PeAnalyzerTests
{
    [Fact]
    public async Task AnalyzeAsync_SyntheticPe_UsesTwoParsersWithoutAPath()
    {
        var bytes = PeFixture.Create();
        var analyzer = new PeAnalyzer(new FixedTrustBackend());
        var result = await analyzer.AnalyzeAsync(
            new ArtifactInput("fixture", new MemoryStream(bytes), bytes.Length),
            new AnalysisContext(), CancellationToken.None);
        result.Layout.Sections.Should().ContainSingle();
        result.Trust.Disposition.Should().Be(TrustDisposition.NoSignature);
        result.Clr.IsManaged.Should().BeFalse();
    }

    [Fact]
    public async Task AnalyzeAsync_RichParserLimit_IsExplicitIncompleteness()
    {
        var bytes = PeFixture.Create();
        var result = await new PeAnalyzer(new FixedTrustBackend()).AnalyzeAsync(
            new ArtifactInput("fixture", new MemoryStream(bytes), bytes.Length),
            new AnalysisContext(128), CancellationToken.None);
        result.RichParserAgreed.Should().BeFalse();
        result.Limitations.Should().ContainSingle(message => message.Contains("limit", StringComparison.Ordinal));
    }

    private sealed class FixedTrustBackend : IAuthenticodeTrustBackend
    {
        public ValueTask<AuthenticodeResult> VerifyAsync(
            Stream stream, AuthenticodePolicy policy, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new AuthenticodeResult(
                unchecked((int)0x800B0100), TrustDisposition.NoSignature, false, null, null));
    }
}
