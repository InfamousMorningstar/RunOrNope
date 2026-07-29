using System.Security.Cryptography;
using System.Text;
using RunOrNope.Analyzers.Content;

namespace RunOrNope.UnitTests.Content;

/// <summary>
/// A container provider driven by an explicit registration table rather than a real
/// archive format. Slice 6a locks the walk's safety properties before any parser exists
/// to argue with, so the tests describe containers directly.
/// </summary>
internal sealed class TestContainerProvider : IContainerProvider
{
    private readonly Dictionary<string, List<ContainerEntry>> containers = new(StringComparer.OrdinalIgnoreCase);

    public static byte[] Leaf(string text) => Encoding.UTF8.GetBytes(text);

    public static string Sha(ReadOnlySpan<byte> content) => Convert.ToHexStringLower(SHA256.HashData(content));

    /// <summary>Declares <paramref name="content"/> to be a container holding <paramref name="entries"/>.</summary>
    public TestContainerProvider Register(byte[] content, params ContainerEntry[] entries)
    {
        containers[Sha(content)] = [.. entries];
        return this;
    }

    /// <summary>An entry whose declared size matches what it delivers.</summary>
    public static ContainerEntry Entry(string name, byte[] content) =>
        new(name, content.Length, content.Length, () => new MemoryStream(content, writable: false));

    /// <summary>An entry whose declared size is a claim the content need not honour.</summary>
    public static ContainerEntry Claiming(string name, long declaredSize, byte[] content, long compressedSize = 0) =>
        new(name, declaredSize, compressedSize, () => new MemoryStream(content, writable: false));

    /// <summary>An entry that streams <paramref name="totalBytes"/> without ever allocating them.</summary>
    public static ContainerEntry Endless(string name, long declaredSize, long totalBytes, long compressedSize = 0) =>
        new(name, declaredSize, compressedSize, () => new ZeroStream(totalBytes));

    public IEnumerable<ContainerEntry>? TryEnumerate(ReadOnlyMemory<byte> content) =>
        containers.TryGetValue(Sha(content.Span), out var entries) ? entries : null;

    /// <summary>Produces bytes on demand, so a "4 GiB" entry costs nothing to describe.</summary>
    private sealed class ZeroStream(long length) : Stream
    {
        private long position;

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => position; set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count)
        {
            var remaining = length - position;
            if (remaining <= 0) return 0;
            var take = (int)Math.Min(count, remaining);
            Array.Clear(buffer, offset, take);
            position += take;
            return take;
        }

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
