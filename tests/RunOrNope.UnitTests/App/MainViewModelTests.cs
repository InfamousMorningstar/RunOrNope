using AwesomeAssertions;
using RunOrNope.App.Services;
using RunOrNope.App.ViewModels;
using RunOrNope.Contracts;
using RunOrNope.Core.Verdicts;
using Xunit;

namespace RunOrNope.UnitTests.App;

public sealed class MainViewModelTests
{
    [Fact]
    public async Task ScanAsync_ProjectsValidatedResultAndIndependentAxes()
    {
        var result = AppTestData.ScanResult();
        var coordinator = new FakeCoordinator(Completed(result));
        using var viewModel = Create(coordinator);
        viewModel.SelectPath("C:\\samples\\sample.exe");

        await viewModel.ScanAsync();

        viewModel.State.Should().Be(ScanUiState.Completed);
        viewModel.AnalysisStatus.Should().Be("Complete");
        viewModel.RiskDisposition.Should().NotBeNullOrWhiteSpace();
        viewModel.CapabilityCards.Should().ContainSingle();
        coordinator.Mode.Should().Be(ScanMode.Quick);
    }

    [Fact]
    public async Task LookupAsync_RequiresConfirmationAndDoesNotChangeVerdict()
    {
        var result = AppTestData.ScanResult();
        var interaction = new FakeInteraction(confirm: false);
        var lookup = new FakeLookup();
        using var viewModel = Create(new FakeCoordinator(Completed(result)), interaction, lookup);
        viewModel.SelectPath("C:\\samples\\sample.exe");
        await viewModel.ScanAsync();
        var verdictBefore = viewModel.RiskDisposition;
        viewModel.SetVirusTotalApiKey("memory-only-key");

        await viewModel.LookupHashAsync();

        lookup.Calls.Should().Be(0);
        interaction.ConfirmedHash.Should().Be(AppTestData.Sha);
        interaction.ConfirmedDestination.Should().Be(new Uri("https://www.virustotal.com"));
        viewModel.RiskDisposition.Should().Be(verdictBefore);
        viewModel.Reputation.Status.Should().Be(HashReputationStatus.Skipped);
    }

    [Fact]
    public void ApiKey_IsPrivateMemoryOnlyAndClearedOnDispose()
    {
        var viewModel = Create(new FakeCoordinator(Completed(AppTestData.ScanResult())));
        viewModel.SetVirusTotalApiKey("session-secret");

        typeof(MainViewModel).GetProperties().Select(property => property.Name)
            .Should().NotContain(name => name.Contains("Key", StringComparison.OrdinalIgnoreCase));
        typeof(MainViewModel).GetFields(
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            .Single(field => field.Name.Contains("virusTotalApiKey", StringComparison.Ordinal))
            .GetValue(viewModel).Should().Be("session-secret");

        viewModel.Dispose();

        typeof(MainViewModel).GetFields(
                System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            .Single(field => field.Name.Contains("virusTotalApiKey", StringComparison.Ordinal))
            .GetValue(viewModel).Should().BeNull();
    }

    [Fact]
    public async Task LookupAsync_ReservesOperationSlotAndCanBeCancelled()
    {
        var lookup = new BlockingLookup();
        using var viewModel = Create(
            new FakeCoordinator(Completed(AppTestData.ScanResult())),
            new FakeInteraction(confirm: true),
            lookup);
        viewModel.SelectPath("C:\\samples\\sample.exe");
        await viewModel.ScanAsync();
        viewModel.SetVirusTotalApiKey("memory-only-key");

        var operation = viewModel.LookupHashAsync();
        await lookup.Started.Task.WaitAsync(TestContext.Current.CancellationToken);

        viewModel.CanStart.Should().BeFalse();
        viewModel.CanLookupHash.Should().BeFalse();
        viewModel.CanCancel.Should().BeTrue();
        viewModel.Cancel();
        await operation;

        lookup.Cancelled.Should().BeTrue();
        viewModel.State.Should().Be(ScanUiState.Completed);
    }

    private static MainViewModel Create(
        IScanCoordinator coordinator,
        IUserInteraction? interaction = null,
        IHashReputationLookup? lookup = null) =>
        new(coordinator, new FakeExport(), lookup ?? new FakeLookup(),
            interaction ?? new FakeInteraction(confirm: true));

    private static CompletedScan Completed(ScanResult result) =>
        new(result, VerdictEngine.Evaluate(result), AppTestData.Sha, 128);

    private sealed class FakeCoordinator(CompletedScan completed) : IScanCoordinator
    {
        public ScanMode Mode { get; private set; }
        public Task<CompletedScan> ScanAsync(string path, ScanMode mode, CancellationToken cancellationToken)
        {
            Mode = mode;
            return Task.FromResult(completed);
        }
    }

    private sealed class FakeExport : IReportExportService
    {
        public Task ExportAsync(ScanResult result, ReportDestination destination, CancellationToken cancellationToken) =>
            Task.CompletedTask;
    }

    private sealed class FakeLookup : IHashReputationLookup
    {
        public int Calls { get; private set; }
        public Task<HashReputationResult> LookupAsync(string sha256, string apiKey, CancellationToken cancellationToken)
        {
            Calls++;
            return Task.FromResult(new HashReputationResult(
                HashReputationStatus.Found, sha256, 0, 0, 10, 50, null));
        }
    }

    private sealed class BlockingLookup : IHashReputationLookup
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool Cancelled { get; private set; }

        public async Task<HashReputationResult> LookupAsync(
            string sha256, string apiKey, CancellationToken cancellationToken)
        {
            Started.SetResult();
            try { await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); }
            catch (OperationCanceledException) { Cancelled = true; throw; }
            throw new InvalidOperationException();
        }
    }

    private sealed class FakeInteraction(bool confirm) : IUserInteraction
    {
        public string? ConfirmedHash { get; private set; }
        public Uri? ConfirmedDestination { get; private set; }
        public string? ChooseSample() => null;
        public ReportDestination? ChooseReportDestination(string suggestedName, ReportFormat format) => null;
        public Task<bool> ConfirmHashLookupAsync(string sha256, Uri destination, CancellationToken cancellationToken)
        {
            ConfirmedHash = sha256;
            ConfirmedDestination = destination;
            return Task.FromResult(confirm);
        }
    }
}
