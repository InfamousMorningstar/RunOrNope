using System.Security.Cryptography;
using AwesomeAssertions;
using RunOrNope.Analyzers.Pe;
using RunOrNope.Contracts;
using RunOrNope.Worker;
using Xunit;

namespace RunOrNope.UnitTests.Pe;

public sealed class WorkerScanTests
{
    [Fact]
    public async Task AnalyzeAsync_NonPeBytes_IsUnsupported()
    {
        var bytes = new byte[128];
        using var stream = new MemoryStream(bytes);

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken);

        result.AnalysisStatus.Should().Be(AnalysisStatus.UnsupportedOrInvalidRootFormat);
        result.Completeness.Should().Be(ArtifactCompleteness.Unsupported);
        result.Observations.Should().BeEmpty();
        RoundTrip(result);
    }

    [Fact]
    public async Task AnalyzeAsync_ValidPe_ProducesRootedStructuralEvidence()
    {
        var bytes = PeFixture.Create();
        using var stream = new MemoryStream(bytes);

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken);

        // Over a MemoryStream, WinTrust is PlatformUnavailable, so a clean parse is
        // legitimately Incomplete rather than Complete; both are non-Unsupported.
        result.AnalysisStatus.Should().BeOneOf(AnalysisStatus.Complete, AnalysisStatus.Incomplete);
        result.Artifacts.Should().ContainSingle()
            .Which.Sha256.Should().Be(Convert.ToHexStringLower(SHA256.HashData(bytes)));
        result.Observations.Should().NotBeEmpty();
        RoundTrip(result);
    }

    [Fact]
    public async Task AnalyzeAsync_TruncatedPe_IsMalformed()
    {
        var bytes = PeFixture.Create(sectionRawSize: 0x200);
        Array.Resize(ref bytes, bytes.Length - 1);
        using var stream = new MemoryStream(bytes);

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Completeness.Should().Be(ArtifactCompleteness.Malformed);
        result.Observations.Should().BeEmpty();
        RoundTrip(result);
    }

    [Theory]
    [InlineData("badimage")]
    [InlineData("overflow")]
    [InlineData("invalidop")]
    [InlineData("argument")]
    [InlineData("io")]
    public async Task AnalyzeAsync_AnalyzerParserFault_IsContainedAsMalformed(string kind)
    {
        // Locks the boundary fix: a parser fault from the analyzer (e.g. the CLR
        // metadata walk throwing BadImageFormatException on a hostile managed PE)
        // must become a Malformed result, never propagate and crash the worker.
        Exception fault = kind switch
        {
            "badimage" => new BadImageFormatException(),
            "overflow" => new OverflowException(),
            "invalidop" => new InvalidOperationException(),
            "argument" => new ArgumentException("simulated parser fault"),
            "io" => new IOException(),
            _ => throw new ArgumentOutOfRangeException(nameof(kind)),
        };
        var bytes = PeFixture.Create();
        using var stream = new MemoryStream(bytes);

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken,
            new ThrowingAnalyzer(fault));

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Completeness.Should().Be(ArtifactCompleteness.Malformed);
        result.Observations.Should().BeEmpty();
    }

    [Fact]
    public async Task AnalyzeAsync_AnalyzerCancellation_IsNotSwallowed()
    {
        // Cancellation and fatal faults must fail closed, not be mislabelled Malformed.
        var bytes = PeFixture.Create();
        using var stream = new MemoryStream(bytes);

        var act = async () => await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken,
            new ThrowingAnalyzer(new OperationCanceledException()));

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task AnalyzeAsync_DeclaredSizeMismatch_IsMalformed()
    {
        var bytes = PeFixture.Create();
        using var stream = new MemoryStream(bytes);

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length + 1, "quick", TestContext.Current.CancellationToken);

        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        result.Completeness.Should().Be(ArtifactCompleteness.Malformed);
    }

    private sealed class ThrowingAnalyzer(Exception fault) : IArtifactAnalyzer
    {
        public ValueTask<PeAnalysisResult> AnalyzeAsync(
            ArtifactInput input, AnalysisContext context, CancellationToken cancellationToken) =>
            throw fault;
    }

    private static void RoundTrip(ScanResult result)
    {
        var json = ScanContractJson.Serialize(result);
        var restored = ScanContractJson.Deserialize(json);
        restored.Should().BeEquivalentTo(result);
    }
}
