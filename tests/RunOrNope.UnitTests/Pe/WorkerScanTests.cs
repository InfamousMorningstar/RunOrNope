using System.Security.Cryptography;
using AwesomeAssertions;
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

    private static void RoundTrip(ScanResult result)
    {
        var json = ScanContractJson.Serialize(result);
        var restored = ScanContractJson.Deserialize(json);
        restored.Should().BeEquivalentTo(result);
    }
}
