using System.Buffers.Binary;
using System.Text;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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
    public async Task Result_reader_rejects_duplicate_members_before_materialization()
    {
        await using var stream = new MemoryStream();
        await WorkerProtocol.WriteFrameAsync(stream,
            Encoding.UTF8.GetBytes("""{"sampleName":"","sampleName":"x"}"""),
            TestContext.Current.CancellationToken);
        stream.Position = 0;

        await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadScanResultAsync(
                stream, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task Result_reader_rejects_collection_limit_before_materialization()
    {
        var values = string.Join(',', Enumerable.Repeat("\"x\"", ContractLimits.MaxNestedStrings + 1));
        var json = $$"""{"sampleName":"","analysisStatus":"incomplete","completeness":"unavailable","artifacts":[],"observations":[],"findings":[],"countervailingFacts":[{{values}}]}""";
        await using var stream = new MemoryStream();
        await WorkerProtocol.WriteFrameAsync(stream, Encoding.UTF8.GetBytes(json),
            TestContext.Current.CancellationToken);
        stream.Position = 0;

        await Assert.ThrowsAsync<WorkerProtocolException>(
            () => WorkerProtocol.ReadScanResultAsync(
                stream, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task Result_reader_bounds_unique_object_members_before_hashset_growth()
    {
        var members = string.Join(',', Enumerable.Range(0, WorkerProtocol.MaxObjectMembers + 1)
            .Select(index => $"\"p{index}\":0"));
        await using var stream = new MemoryStream();
        await WorkerProtocol.WriteFrameAsync(stream, Encoding.UTF8.GetBytes($"{{{members}}}"),
            TestContext.Current.CancellationToken);
        stream.Position = 0;
        await Assert.ThrowsAsync<WorkerProtocolException>(() =>
            WorkerProtocol.ReadScanResultAsync(
                stream, TestContext.Current.CancellationToken).AsTask());
    }

    [Fact]
    public async Task Authenticated_self_contained_worker_completes_benign_ipc()
    {
        var bytes = new byte[] { 0x4D, 0x5A, 0, 0 };
        var path = Path.Combine(Path.GetTempPath(), $"runornope-benign-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, bytes, TestContext.Current.CancellationToken);
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            var (root, manifest) = CreateAuthenticatedPackageForTests(
                "RunOrNope.Worker", "RunOrNope.Worker.exe");
            var broker = new WorkerBroker(root, manifest);

            var result = await broker.AnalyzeAsync(
                handle, new ScanRequest(path, ScanMode.Quick), TestContext.Current.CancellationToken);

            // The worker ran real analysis over IPC: a 4-byte MZ stub is not a valid PE,
            // so it is correctly classified Unsupported. A non-IsolationUnavailable result
            // with the correct root hash also proves the broker's independent hash
            // cross-check passed (a mismatch would fail closed to IsolationUnavailable).
            Assert.Equal(AnalysisStatus.UnsupportedOrInvalidRootFormat, result.AnalysisStatus);
            var rootArtifact = Assert.Single(result.Artifacts);
            Assert.Equal(Convert.ToHexStringLower(SHA256.HashData(bytes)), rootArtifact.Sha256);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task Live_appcontainer_denies_network_dns_proxy_websocket_and_http()
    {
        using var ipv4 = new TcpListener(IPAddress.Loopback, 0);
        using var ipv6 = new TcpListener(IPAddress.IPv6Loopback, 0);
        using var proxy = new TcpListener(IPAddress.Loopback, 0);
        var privateAddress = Dns.GetHostAddresses(Dns.GetHostName())
            .First(address => address.AddressFamily == AddressFamily.InterNetwork &&
                              !IPAddress.IsLoopback(address));
        using var dns = new UdpClient(new IPEndPoint(privateAddress, 0));
        using var privateListener = new TcpListener(privateAddress, 0);
        ipv4.Start(); ipv6.Start(); proxy.Start(); privateListener.Start();
        var path = Path.Combine(Path.GetTempPath(), $"runornope-probe-{Guid.NewGuid():N}.bin");
        var outside = Directory.CreateTempSubdirectory("runornope-outside-");
        await File.WriteAllBytesAsync(path, [1], TestContext.Current.CancellationToken);
        try
        {
            var (root, manifest) = CreateAuthenticatedPackageForTests(
                "RunOrNope.IsolationProbe", "RunOrNope.IsolationProbe.exe");
            var broker = new WorkerBroker(root, manifest, prepareOutputForTesting: output =>
                Directory.CreateSymbolicLink(Path.Combine(output, "escape-link"), outside.FullName));
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            var result = await broker.AnalyzeProbeAsync(handle, new WorkerProbeRequest(
                "matrix",
                ((IPEndPoint)ipv4.LocalEndpoint).Port,
                ((IPEndPoint)ipv6.LocalEndpoint).Port,
                ((IPEndPoint)proxy.LocalEndpoint).Port,
                privateAddress.ToString(),
                ((IPEndPoint)privateListener.LocalEndpoint).Port,
                ((IPEndPoint)dns.Client.LocalEndPoint!).Port),
                TestContext.Current.CancellationToken);

            Assert.True(result.AnalysisStatus == AnalysisStatus.Incomplete,
                string.Join(Environment.NewLine, result.CountervailingFacts));
            foreach (var name in new[] { "ipv4", "ipv6", "private", "http", "proxy", "websocket" })
                Assert.Contains($"probe:{name}=denied", result.CountervailingFacts);
            Assert.True(result.CountervailingFacts.Contains("probe:dns=send-accepted"),
                string.Join(Environment.NewLine, result.CountervailingFacts));
            Assert.Contains("probe:output-write=allowed", result.CountervailingFacts);
            Assert.Contains("probe:output-traversal=denied", result.CountervailingFacts);
            Assert.Contains("probe:output-reparse=denied", result.CountervailingFacts);
            Assert.Empty(outside.EnumerateFileSystemInfos());
            Assert.False(ipv4.Pending());
            Assert.False(ipv6.Pending());
            Assert.False(proxy.Pending());
            Assert.False(privateListener.Pending());
            using (var dnsGrace = new CancellationTokenSource(TimeSpan.FromMilliseconds(500)))
            {
                try
                {
                    var packet = await dns.ReceiveAsync(dnsGrace.Token);
                    Assert.Fail(
                        $"The isolated DNS probe delivered {packet.Buffer.Length} bytes to the controlled listener.");
                }
                catch (OperationCanceledException) when (dnsGrace.IsCancellationRequested)
                {
                    // No packet arrived during the bounded post-result window.
                }
            }
        }
        finally
        {
            File.Delete(path);
            outside.Delete(true);
        }
    }

    [Fact]
    public async Task Live_appcontainer_and_job_deny_child_process_creation()
    {
        var path = Path.Combine(Path.GetTempPath(), $"runornope-child-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, [1], TestContext.Current.CancellationToken);
        try
        {
            var (root, manifest) = CreateAuthenticatedPackageForTests(
                "RunOrNope.IsolationProbe", "RunOrNope.IsolationProbe.exe");
            var broker = new WorkerBroker(root, manifest);
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            var result = await broker.AnalyzeProbeAsync(handle,
                new WorkerProbeRequest("child"), TestContext.Current.CancellationToken);
            Assert.Equal(AnalysisStatus.Incomplete, result.AnalysisStatus);
            Assert.Contains("probe:child=denied", result.CountervailingFacts);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Explicit_handle_list_does_not_inherit_unlisted_broker_handle()
    {
        var path = Path.Combine(Path.GetTempPath(), $"runornope-handles-{Guid.NewGuid():N}.bin");
        var sentinelPath = Path.Combine(Path.GetTempPath(), $"runornope-unlisted-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, [1], TestContext.Current.CancellationToken);
        await File.WriteAllBytesAsync(sentinelPath, [2], TestContext.Current.CancellationToken);
        try
        {
            var (root, manifest) = CreateAuthenticatedPackageForTests(
                "RunOrNope.IsolationProbe", "RunOrNope.IsolationProbe.exe");
            var broker = new WorkerBroker(root, manifest);
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            using var sentinel = File.OpenHandle(sentinelPath, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            Assert.True(NativeMethods.SetHandleInformation(
                sentinel, NativeMethods.HandleFlagInherit, NativeMethods.HandleFlagInherit));
            var result = await broker.AnalyzeProbeAsync(handle,
                new WorkerProbeRequest("handle", SentinelHandle: sentinel.DangerousGetHandle().ToInt64()),
                TestContext.Current.CancellationToken);
            Assert.Equal(AnalysisStatus.Incomplete, result.AnalysisStatus);
            Assert.Contains("probe:unexpected-handle=denied", result.CountervailingFacts);
        }
        finally
        {
            File.Delete(path);
            File.Delete(sentinelPath);
        }
    }

    [Fact]
    public async Task Closing_job_object_terminates_a_live_probe()
    {
        var (root, _) = CreateAuthenticatedPackageForTests(
            "RunOrNope.IsolationProbe", "RunOrNope.IsolationProbe.exe");
        using var process = Process.Start(new ProcessStartInfo(
            Path.Combine(root, "RunOrNope.IsolationProbe.exe"), "--wait")
        {
            UseShellExecute = false,
            CreateNoWindow = true
        });
        Assert.NotNull(process);
        var job = JobObject.Create(WorkerIsolationPolicy.Default);
        try
        {
            Assert.True(NativeMethods.AssignProcessToJobObject(
                job.Handle, process.SafeHandle.DangerousGetHandle()));
            Assert.False(process.HasExited);
        }
        finally
        {
            job.Dispose();
        }
        await process.WaitForExitAsync(TestContext.Current.CancellationToken)
            .WaitAsync(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);
        Assert.True(process.HasExited);
    }

    [Theory]
    [InlineData("memory")]
    [InlineData("cpu")]
    [InlineData("timeout")]
    public async Task Live_job_and_broker_limits_stop_hostile_worker(string operation)
    {
        var path = Path.Combine(Path.GetTempPath(), $"runornope-limit-{Guid.NewGuid():N}.bin");
        await File.WriteAllBytesAsync(path, [1], TestContext.Current.CancellationToken);
        try
        {
            var (root, manifest) = CreateAuthenticatedPackageForTests(
                "RunOrNope.IsolationProbe", "RunOrNope.IsolationProbe.exe");
            var baseline = WorkerIsolationPolicy.Default;
            var policy = baseline with
            {
                ProcessMemoryBytes = operation == "memory" ? 64L * 1024 * 1024 : baseline.ProcessMemoryBytes,
                ProcessCpuTime = operation == "cpu" ? TimeSpan.FromMilliseconds(500) : baseline.ProcessCpuTime,
                WallClockTimeout = operation == "timeout" ? TimeSpan.FromMilliseconds(500) : TimeSpan.FromSeconds(10)
            };
            var broker = new WorkerBroker(root, manifest, policy);
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Delete);
            var result = await broker.AnalyzeProbeAsync(handle,
                new WorkerProbeRequest(operation), TestContext.Current.CancellationToken);

            Assert.Equal(AnalysisStatus.IsolationUnavailable, result.AnalysisStatus);
            Assert.Empty(result.Findings);
        }
        finally { File.Delete(path); }
    }

    internal static (string Root, WorkerPackageManifest Manifest) CreateAuthenticatedPackageForTests(
        string projectName, string entryPoint)
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "RunOrNope.slnx")))
            root = root.Parent;
        Assert.NotNull(root);
        var projectRoot = projectName == "RunOrNope.Worker" ? "src" : "tests";
        var packageRoot = Path.Combine(root.FullName, projectRoot, projectName, "bin", "Release",
            "net10.0-windows10.0.19041.0", "win-x64");
        var entries = Directory.EnumerateFiles(packageRoot)
            .Where(path => !path.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))
            .Select(path =>
            {
                using var stream = File.OpenRead(path);
                return new WorkerPackageFile(Path.GetFileName(path),
                    Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(), stream.Length);
            })
            .OrderBy(entry => entry.Name, StringComparer.Ordinal)
            .ToImmutableArray();
        var document = new WorkerPackageDocument(1, "test-build", entryPoint, entries);
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var json = WorkerPackageManifest.Serialize(document);
        return (packageRoot, WorkerPackageManifest.Authenticate(
            json, signer.SignData(json, HashAlgorithmName.SHA256),
            signer.ExportSubjectPublicKeyInfo()));
    }
}
