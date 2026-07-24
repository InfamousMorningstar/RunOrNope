namespace RunOrNope.Worker;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length != 5 || args[0] != "--broker" ||
            !long.TryParse(args[1], out var sampleValue) ||
            !long.TryParse(args[2], out var outputValue) ||
            !long.TryParse(args[3], out var requestValue) ||
            !long.TryParse(args[4], out var responseValue))
            return 64;
        try
        {
            using var sample = new Microsoft.Win32.SafeHandles.SafeFileHandle(
                checked((nint)sampleValue), ownsHandle: false);
            using var requestHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(
                checked((nint)requestValue), ownsHandle: false);
            using var responseHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(
                checked((nint)responseValue), ownsHandle: false);
            using var outputHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(
                checked((nint)outputValue), ownsHandle: false);
            await using var requestStream = new FileStream(requestHandle, FileAccess.Read);
            await using var responseStream = new FileStream(responseHandle, FileAccess.Write);
            var request = await WorkerProtocol.ReadRequestAsync(requestStream, CancellationToken.None);
            if (sample.IsInvalid || outputHandle.IsInvalid || request.SampleSize < 0) return 65;

            var result = new RunOrNope.Contracts.ScanResult(
                string.Empty,
                RunOrNope.Contracts.AnalysisStatus.Incomplete,
                RunOrNope.Contracts.ArtifactCompleteness.Unavailable,
                System.Collections.Immutable.ImmutableArray<RunOrNope.Contracts.ArtifactNode>.Empty,
                System.Collections.Immutable.ImmutableArray<RunOrNope.Contracts.Observation>.Empty,
                System.Collections.Immutable.ImmutableArray<RunOrNope.Contracts.CapabilityFinding>.Empty,
                System.Collections.Immutable.ImmutableArray.Create(
                    "The isolated worker started successfully; analyzers are not installed yet."));
            var response = System.Text.Encoding.UTF8.GetBytes(
                RunOrNope.Contracts.ScanContractJson.Serialize(result));
            await WorkerProtocol.WriteFrameAsync(responseStream, response, CancellationToken.None);
            return 0;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or WorkerProtocolException)
        {
            return 66;
        }
    }
}
