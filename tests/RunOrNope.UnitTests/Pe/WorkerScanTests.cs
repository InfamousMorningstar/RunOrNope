using System.Collections.Immutable;
using System.Security.Cryptography;
using AwesomeAssertions;
using RunOrNope.Analyzers.Pe;
using RunOrNope.Contracts;
using RunOrNope.Core.Verdicts;
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

    [Fact]
    public async Task AnalyzeAsync_InjectionImports_YieldCautionVerdict()
    {
        var bytes = PeFixture.Create();
        using var stream = new MemoryStream(bytes);
        var analysis = AnalysisWithImports(
            "kernel32.dll!VirtualAllocEx", "kernel32.dll!WriteProcessMemory",
            "kernel32.dll!CreateRemoteThread");

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken,
            new FixedAnalyzer(analysis));

        result.Findings.Should().Contain(finding => finding.Family == RiskFamily.ProcessManipulation);
        VerdictEngine.Evaluate(result).RiskDisposition.Should().Be(RiskDisposition.CautionWarranted);
        RoundTrip(result);
    }

    [Fact]
    public async Task AnalyzeAsync_BenignImports_YieldFewMaterialConcerns()
    {
        var bytes = PeFixture.Create();
        using var stream = new MemoryStream(bytes);
        var analysis = AnalysisWithImports("kernel32.dll!CreateFileW", "kernel32.dll!ReadFile");

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken,
            new FixedAnalyzer(analysis));

        result.Findings.Should().BeEmpty();
        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        VerdictEngine.Evaluate(result).RiskDisposition.Should().Be(RiskDisposition.FewMaterialStaticConcerns);
        RoundTrip(result);
    }

    [Fact]
    public async Task AnalyzeAsync_OrdinaryDesktopAppImports_YieldFewMaterialConcerns()
    {
        // A realistic benign import set: a plugin loader, an update check, a debugger
        // check from the CRT, and double-buffered painting. Every presence-only rule
        // fires, and they must still not add up to a caution — otherwise the first
        // slice that produces a disposition would flag ordinary software.
        var bytes = PeFixture.Create();
        using var stream = new MemoryStream(bytes);
        var analysis = AnalysisWithImports(
            "kernel32.dll!LoadLibraryW", "kernel32.dll!GetProcAddress",
            "ws2_32.dll!connect", "kernel32.dll!IsDebuggerPresent",
            "gdi32.dll!BitBlt", "gdi32.dll!CreateCompatibleBitmap",
            "kernel32.dll!CreateFileW", "kernel32.dll!ReadFile");

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken,
            new FixedAnalyzer(analysis));

        result.Findings.Should().NotBeEmpty();
        result.Findings.Should().OnlyContain(finding =>
            finding.EvidenceStatus == EvidenceStatus.ApiOrLibraryPresenceOnly);
        result.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        VerdictEngine.Evaluate(result).RiskDisposition.Should().Be(RiskDisposition.FewMaterialStaticConcerns);
        RoundTrip(result);
    }

    [Fact]
    public async Task AnalyzeAsync_PackedSampleWithNoReadableImports_WithholdsDisposition()
    {
        // The failure this guards: a packed or ordinal-only sample matches no rule, so
        // it produces no findings, and "no findings" would otherwise score as the most
        // favorable disposition available. Absence of visible evidence must withhold a
        // verdict, not earn a good one.
        var bytes = PeFixture.Create();
        using var stream = new MemoryStream(bytes);

        var result = await WorkerScan.AnalyzeAsync(
            stream, bytes.Length, "quick", TestContext.Current.CancellationToken,
            new FixedAnalyzer(AnalysisWithImports()));

        result.Findings.Should().BeEmpty();
        result.AnalysisStatus.Should().Be(AnalysisStatus.Incomplete);
        VerdictEngine.Evaluate(result).RiskDisposition.Should().BeNull();
        RoundTrip(result);
    }

    private static PeAnalysisResult AnalysisWithImports(params string[] imports)
    {
        var section = new PeSection(".text", 0x1000, 0x200, 0x200, 0x200, 0x6000_0020);
        var layout = new PeLayout(
            true, 0x8664, 0x1000, 0x400, ImmutableArray.Create(section),
            null, 0, 0, 0, ImmutableArray<string>.Empty);
        var clr = new ClrAnalysisResult(
            false, null, ImmutableArray<string>.Empty, ImmutableArray<ClrMethodObservation>.Empty,
            ImmutableArray<ClrExternalReference>.Empty, false, ImmutableArray<string>.Empty);
        var trust = new AuthenticodeResult(0, TrustDisposition.NoSignature, false, null, null, 0);
        var rich = new RichPeSummary(
            1, imports.Length, 0, 0, false, false,
            [.. imports], ImmutableArray<string>.Empty);
        return new PeAnalysisResult(layout, clr, trust, rich, RichParserAgreed: true, ImmutableArray<string>.Empty);
    }

    private sealed class ThrowingAnalyzer(Exception fault) : IArtifactAnalyzer
    {
        public ValueTask<PeAnalysisResult> AnalyzeAsync(
            ArtifactInput input, AnalysisContext context, CancellationToken cancellationToken) =>
            throw fault;
    }

    private sealed class FixedAnalyzer(PeAnalysisResult result) : IArtifactAnalyzer
    {
        public ValueTask<PeAnalysisResult> AnalyzeAsync(
            ArtifactInput input, AnalysisContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(result);
    }

    private static void RoundTrip(ScanResult result)
    {
        var json = ScanContractJson.Serialize(result);
        var restored = ScanContractJson.Deserialize(json);
        restored.Should().BeEquivalentTo(result);
    }
}
