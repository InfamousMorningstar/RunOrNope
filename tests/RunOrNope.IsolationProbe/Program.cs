using System.Collections.Immutable;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using Microsoft.Win32.SafeHandles;
using RunOrNope.Contracts;
using RunOrNope.Worker;
using System.Runtime.InteropServices;

if (args is ["--child"]) return 0;
if (args is ["--wait"])
{
    await Task.Delay(Timeout.InfiniteTimeSpan);
    return 0;
}
if (args.Length != 5 || args[0] != "--broker" ||
    !long.TryParse(args[1], out var sampleValue) ||
    !long.TryParse(args[2], out var outputValue) ||
    !long.TryParse(args[3], out var requestValue) ||
    !long.TryParse(args[4], out var responseValue)) return 64;

using var sample = new SafeFileHandle(checked((nint)sampleValue), false);
using var output = new SafeFileHandle(checked((nint)outputValue), false);
using var requestHandle = new SafeFileHandle(checked((nint)requestValue), false);
using var responseHandle = new SafeFileHandle(checked((nint)responseValue), false);
await using var requestStream = new FileStream(requestHandle, FileAccess.Read);
await using var responseStream = new FileStream(responseHandle, FileAccess.Write);
var request = await WorkerProtocol.ReadRequestAsync(requestStream, CancellationToken.None);
var probe = request.Probe ?? throw new InvalidOperationException("Probe request required.");

if (probe.Operation == "memory")
{
    var blocks = new List<byte[]>();
    while (true) blocks.Add(GC.AllocateUninitializedArray<byte>(16 * 1024 * 1024));
}
if (probe.Operation == "cpu")
{
    while (true) Thread.SpinWait(1_000_000);
}
if (probe.Operation == "timeout")
{
    await Task.Delay(Timeout.InfiniteTimeSpan);
}
if (probe.Operation == "child")
{
    var childFacts = new List<string>();
    try
    {
        using var child = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "--child")
        {
            UseShellExecute = false,
            CreateNoWindow = true
        }) ?? throw new InvalidOperationException();
        childFacts.Add("probe:child=ALLOWED");
        child.Kill();
    }
    catch (Exception)
    {
        childFacts.Add("probe:child=denied");
    }
    await WriteResult(childFacts);
    return 0;
}
if (probe.Operation == "handle")
{
    var handleFacts = new List<string>();
    try
    {
        using var unexpected = new SafeFileHandle(checked((nint)probe.SentinelHandle), false);
        _ = RandomAccess.Read(unexpected, new byte[1], 0);
        handleFacts.Add("probe:unexpected-handle=ALLOWED");
    }
    catch (Exception)
    {
        handleFacts.Add("probe:unexpected-handle=denied");
    }
    await WriteResult(handleFacts);
    return 0;
}

using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
var facts = new List<string>();
await Probe("ipv4", () => ConnectAsync(IPAddress.Loopback, probe.Ipv4Port, timeout.Token));
await Probe("ipv6", () => ConnectAsync(IPAddress.IPv6Loopback, probe.Ipv6Port, timeout.Token));
await Probe("private", () => ConnectAsync(IPAddress.Parse(probe.PrivateAddress!), probe.PrivatePort, timeout.Token));
await Probe("http", async () =>
{
    using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
    _ = await client.GetAsync($"http://127.0.0.1:{probe.Ipv4Port}/", timeout.Token);
});
await Probe("proxy", async () =>
{
    using var handler = new HttpClientHandler
    {
        Proxy = new WebProxy($"http://127.0.0.1:{probe.ProxyPort}"),
        UseProxy = true
    };
    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2) };
    _ = await client.GetAsync("http://example.invalid/", timeout.Token);
});
await Probe("websocket", async () =>
{
    using var socket = new System.Net.WebSockets.ClientWebSocket();
    await socket.ConnectAsync(new Uri($"ws://127.0.0.1:{probe.Ipv4Port}/"), timeout.Token);
});
try
{
    using var dns = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    byte[] query =
    [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x09,
        (byte)'r', (byte)'u', (byte)'n', (byte)'o', (byte)'r', (byte)'n', (byte)'o', (byte)'p', (byte)'e',
        0x04, (byte)'t', (byte)'e', (byte)'s', (byte)'t', 0x00,
        0x00, 0x01, 0x00, 0x01
    ];
    dns.Connect(new IPEndPoint(IPAddress.Parse(probe.PrivateAddress!), probe.DnsPort));
    _ = dns.Send(query, SocketFlags.None);
    // A successful UDP send only means Winsock accepted the datagram locally.
    // The broker-side listener is the authority on whether any packet escaped.
    facts.Add("probe:dns=send-accepted");
}
catch (SocketException exception) when (exception.SocketErrorCode == SocketError.AccessDenied)
{
    facts.Add("probe:dns=denied-access");
}
catch (Exception exception)
{
    facts.Add($"probe:dns=wrong-failure-{exception.GetType().Name}");
}
facts.Add("probe:child=not-tested");
facts.Add("probe:unexpected-handle=not-tested");
facts.Add(TryCreateRelative(output, "probe-output.bin")
    ? "probe:output-write=allowed"
    : "probe:output-write=DENIED");
facts.Add(!TryCreateRelative(output, @"..\probe-escape.bin")
    ? "probe:output-traversal=denied"
    : "probe:output-traversal=ALLOWED");
facts.Add(!TryCreateRelative(output, @"escape-link\probe.bin")
    ? "probe:output-reparse=denied"
    : "probe:output-reparse=ALLOWED");

await WriteResult(facts);
return 0;

async Task WriteResult(IEnumerable<string> resultFacts)
{
    var result = new ScanResult(string.Empty, AnalysisStatus.Incomplete,
        ArtifactCompleteness.Unavailable, ImmutableArray<ArtifactNode>.Empty,
        ImmutableArray<Observation>.Empty, ImmutableArray<CapabilityFinding>.Empty,
        resultFacts.ToImmutableArray());
    await WorkerProtocol.WriteFrameAsync(responseStream,
        System.Text.Encoding.UTF8.GetBytes(ScanContractJson.Serialize(result)), CancellationToken.None);
}

async Task Probe(string name, Func<Task> action)
{
    try
    {
        await action();
        facts.Add($"probe:{name}=ALLOWED");
    }
    catch (Exception)
    {
        facts.Add($"probe:{name}=denied");
    }
}

static async Task ConnectAsync(IPAddress address, int port, CancellationToken token)
{
    using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
    await socket.ConnectAsync(new IPEndPoint(address, port), token);
}

static bool TryCreateRelative(SafeFileHandle root, string name)
{
    var text = Marshal.StringToHGlobalUni(name);
    var unicodePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
    var added = false;
    try
    {
        Marshal.StructureToPtr(new UnicodeString
        {
            Length = checked((ushort)(name.Length * 2)),
            MaximumLength = checked((ushort)((name.Length + 1) * 2)),
            Buffer = text
        }, unicodePointer, false);
        root.DangerousAddRef(ref added);
        var attributes = new ObjectAttributes
        {
            Length = Marshal.SizeOf<ObjectAttributes>(),
            RootDirectory = root.DangerousGetHandle(),
            ObjectName = unicodePointer,
            Attributes = 0x40
        };
        var status = ProbeNative.NtCreateFile(out var file, 0x40000000 | 0x00100000,
            ref attributes, out _, IntPtr.Zero, 0, 0x1, 2, 0x40 | 0x20, IntPtr.Zero, 0);
        if (file != IntPtr.Zero && file != new IntPtr(-1)) ProbeNative.CloseHandle(file);
        return status >= 0;
    }
    finally
    {
        if (added) root.DangerousRelease();
        Marshal.FreeHGlobal(unicodePointer);
        Marshal.FreeHGlobal(text);
    }
}

[StructLayout(LayoutKind.Sequential)]
struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
[StructLayout(LayoutKind.Sequential)]
struct ObjectAttributes
{
    public int Length;
    public IntPtr RootDirectory, ObjectName;
    public uint Attributes;
    public IntPtr SecurityDescriptor, SecurityQualityOfService;
}
[StructLayout(LayoutKind.Sequential)]
struct IoStatusBlock { public IntPtr Status, Information; }

static class ProbeNative
{
    [DllImport("ntdll.dll")]
    internal static extern int NtCreateFile(out IntPtr fileHandle, uint desiredAccess,
        ref ObjectAttributes objectAttributes, out IoStatusBlock ioStatusBlock,
        IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition,
        uint createOptions, IntPtr eaBuffer, uint eaLength);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr handle);
}
