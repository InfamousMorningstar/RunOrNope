using RunOrNope.App.Services;
using RunOrNope.Broker.Windows;
using RunOrNope.Contracts;
using RunOrNope.Intake;
using Xunit;

namespace RunOrNope.IntegrationTests.App;

public sealed class ScanWorkflowTests : IDisposable
{
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"ronp-workflow-{Guid.NewGuid():N}.exe");

    public ScanWorkflowTests() => File.WriteAllBytes(_path, [0x4D, 0x5A, .. new byte[126]]);

    public void Dispose()
    {
        try { File.Delete(_path); } catch (IOException) { }
    }

    [Fact]
    public async Task IntakeLeaseFlowsToFakeBrokerWithoutWorkerOrPathReopen()
    {
        var broker = new FakeBroker();
        var workflow = new ScanCoordinator(broker);

        var completed = await workflow.ScanAsync(
            _path, ScanMode.Quick, TestContext.Current.CancellationToken);

        Assert.NotNull(broker.Lease);
        Assert.Equal(string.Empty, broker.Request!.Path);
        Assert.Equal(broker.Lease!.Sha256, completed.Sha256);
        Assert.Equal(AnalysisStatus.Complete, completed.Result.AnalysisStatus);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await broker.Lease.ReadAsync(new byte[1], 0, CancellationToken.None));
    }

    private sealed class FakeBroker : IWorkerBroker
    {
        public SafeFileLease? Lease { get; private set; }
        public ScanRequest? Request { get; private set; }

        public Task<ScanResult> AnalyzeAsync(
            SafeFileLease sample, ScanRequest request, CancellationToken cancellationToken)
        {
            Lease = sample;
            Request = request;
            return Task.FromResult(new ScanResult(
                "sample.exe", AnalysisStatus.Complete, ArtifactCompleteness.Complete,
                [new ArtifactNode("root", "sample.exe", sample.Sha256, sample.Size,
                    ArtifactCompleteness.Complete, [], ApplicationLinkage.Unknown)],
                [], [], []));
        }
    }
}
