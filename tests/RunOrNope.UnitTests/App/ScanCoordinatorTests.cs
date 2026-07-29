using System.Collections.Immutable;
using AwesomeAssertions;
using RunOrNope.App.Services;
using RunOrNope.Broker.Windows;
using RunOrNope.Contracts;
using RunOrNope.Intake;
using Xunit;

namespace RunOrNope.UnitTests.App;

public sealed class ScanCoordinatorTests : IDisposable
{
    private const string Sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"ronp-app-{Guid.NewGuid():N}.exe");

    public ScanCoordinatorTests() => File.WriteAllBytes(_path, [0x4D, 0x5A, .. new byte[126]]);

    public void Dispose()
    {
        try { File.Delete(_path); } catch (IOException) { }
    }

    [Fact]
    public async Task ScanAsync_PassesLeaseAndEmptyPathToBroker()
    {
        var broker = new FakeBroker();
        var coordinator = new ScanCoordinator(broker);

        var completed = await coordinator.ScanAsync(_path, ScanMode.Deep, TestContext.Current.CancellationToken);

        broker.Request.Should().Be(new ScanRequest(string.Empty, ScanMode.Deep));
        broker.Lease.Should().NotBeNull();
        completed.Sha256.Should().Be(broker.Lease!.Sha256);
        completed.Verdict.AnalysisStatus.Should().Be(AnalysisStatus.Complete);
        var read = async () => await broker.Lease.ReadAsync(new byte[1], 0, CancellationToken.None);
        await read.Should().ThrowAsync<ObjectDisposedException>("the coordinator owns and disposes the intake lease");
    }

    [Fact]
    public async Task ScanAsync_RejectsWorkerIdentityMismatch()
    {
        var broker = new FakeBroker(wrongIdentity: true);
        var coordinator = new ScanCoordinator(broker);

        var scan = async () => await coordinator.ScanAsync(_path, ScanMode.Quick, TestContext.Current.CancellationToken);

        await scan.Should().ThrowAsync<ContractValidationException>();
    }

    [Fact]
    public async Task ScanAsync_PreservesIsolationUnavailableAsIndependentStatus()
    {
        var broker = new FakeBroker(isolationUnavailable: true);
        var coordinator = new ScanCoordinator(broker);

        var completed = await coordinator.ScanAsync(_path, ScanMode.Quick, TestContext.Current.CancellationToken);

        completed.Result.AnalysisStatus.Should().Be(AnalysisStatus.IsolationUnavailable);
        completed.Verdict.RiskDisposition.Should().BeNull();
    }

    private sealed class FakeBroker(bool wrongIdentity = false, bool isolationUnavailable = false) : IWorkerBroker
    {
        public SafeFileLease? Lease { get; private set; }
        public ScanRequest? Request { get; private set; }

        public Task<ScanResult> AnalyzeAsync(
            SafeFileLease sample, ScanRequest request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Lease = sample;
            Request = request;
            if (isolationUnavailable)
            {
                return Task.FromResult(new ScanResult(
                    string.Empty, AnalysisStatus.IsolationUnavailable, ArtifactCompleteness.Unavailable,
                    [], [], [], ["Required isolation was unavailable."]));
            }

            var sha = wrongIdentity ? Sha : sample.Sha256;
            return Task.FromResult(new ScanResult(
                "sample.exe", AnalysisStatus.Complete, ArtifactCompleteness.Complete,
                [new ArtifactNode("root", "sample.exe", sha, sample.Size,
                    ArtifactCompleteness.Complete, [], ApplicationLinkage.Unknown)],
                ImmutableArray<Observation>.Empty,
                ImmutableArray<CapabilityFinding>.Empty,
                ImmutableArray<string>.Empty));
        }
    }
}
