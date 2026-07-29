using RunOrNope.Broker.Windows;
using RunOrNope.Contracts;
using RunOrNope.Core.Verdicts;
using RunOrNope.Intake;

namespace RunOrNope.App.Services;

public sealed class ScanCoordinator(IWorkerBroker broker) : IScanCoordinator
{
    public async Task<CompletedScan> ScanAsync(
        string path, ScanMode mode, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!Enum.IsDefined(mode)) throw new ArgumentOutOfRangeException(nameof(mode));

        using var lease = await SafeFileIntake.OpenAsync(
            path, IntakePolicy.Default, cancellationToken).ConfigureAwait(false);
        var result = await broker.AnalyzeAsync(
            lease, new ScanRequest(string.Empty, mode), cancellationToken).ConfigureAwait(false);
        ContractValidator.Validate(result);
        if (!result.Artifacts.IsDefaultOrEmpty)
            WorkerResultIntegrity.EnsureRootIdentity(result, lease.Sha256, lease.Size);
        return new(result, VerdictEngine.Evaluate(result), lease.Sha256, lease.Size);
    }
}
