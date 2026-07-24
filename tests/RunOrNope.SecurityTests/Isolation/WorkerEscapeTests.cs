using System.Buffers.Binary;
using System.Text;
using RunOrNope.Worker;
using RunOrNope.Broker.Windows;
using RunOrNope.Contracts;
using Xunit;

namespace RunOrNope.SecurityTests.Isolation;

public sealed class WorkerEscapeTests
{
    [Fact]
    public async Task Frame_reader_rejects_oversize_before_reading_payload()
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, WorkerProtocol.MaxFrameBytes + 1);
        await using var stream = new MemoryStream(bytes);

        await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadFrameAsync(stream, CancellationToken.None).AsTask());
        Assert.Equal(4, stream.Position);
    }

    [Fact]
    public async Task Frame_reader_rejects_negative_length()
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(bytes, -1);
        await using var stream = new MemoryStream(bytes);

        await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadFrameAsync(stream, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Frame_reader_rejects_truncated_and_invalid_utf8_payloads()
    {
        await using var truncated = new MemoryStream([3, 0, 0, 0, 1]);
        await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadFrameAsync(truncated, CancellationToken.None).AsTask());

        await using var invalid = new MemoryStream([2, 0, 0, 0, 0xC3, 0x28]);
        await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadUtf8FrameAsync(invalid, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Protocol_round_trips_a_bounded_versioned_envelope()
    {
        await using var stream = new MemoryStream();
        var envelope = new WorkerRequestEnvelope(WorkerProtocol.CurrentVersion, "deep", 1234);

        await WorkerProtocol.WriteJsonFrameAsync(stream, envelope, CancellationToken.None);
        stream.Position = 0;
        var actual = await WorkerProtocol.ReadJsonFrameAsync<WorkerRequestEnvelope>(
            stream, CancellationToken.None);

        Assert.Equal(envelope, actual);
    }

    [Fact]
    public async Task Protocol_rejects_unknown_version_and_trailing_json()
    {
        var bad = Encoding.UTF8.GetBytes("""{"version":999,"mode":"quick","sampleSize":1} {}""");
        await using var stream = new MemoryStream();
        await WorkerProtocol.WriteFrameAsync(stream, bad, CancellationToken.None);
        stream.Position = 0;

        await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadRequestAsync(stream, CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task Unpackaged_dev_worker_fails_closed_when_appcontainer_cannot_load_runtime()
    {
        var path = Path.Combine(Path.GetTempPath(), $"runornope-benign-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, [0x4D, 0x5A, 0, 0],
            TestContext.Current.CancellationToken);
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            var broker = new WorkerBroker(
                Path.Combine(AppContext.BaseDirectory, "RunOrNope.Worker.exe"));

            var result = await broker.AnalyzeAsync(
                handle, new ScanRequest(path, ScanMode.Quick), TestContext.Current.CancellationToken);

            Assert.Equal(AnalysisStatus.IsolationUnavailable, result.AnalysisStatus);
            Assert.Empty(result.Findings);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
