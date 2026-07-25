using System.Buffers.Binary;
using System.Security.Cryptography;
using RunOrNope.Analyzers.Pe;
using RunOrNope.Contracts;

namespace RunOrNope.Worker;

/// <summary>
/// In-sandbox analysis core: turns the read-only sample stream into a validated
/// <see cref="ScanResult"/>. Protocol-free and dependency-light so it can be unit
/// tested without the AppContainer transport. Format support is re-derived from the
/// bytes here — the broker's claim is never trusted for parsing — and a parser
/// rejection becomes structured incompleteness, never a fault crossing the boundary.
/// </summary>
internal static class WorkerScan
{
    private const int MaxPeHeaderOffset = 1024 * 1024;

    internal static async ValueTask<ScanResult> AnalyzeAsync(
        Stream sample, long declaredSize, string mode, CancellationToken cancellationToken,
        IArtifactAnalyzer? analyzer = null)
    {
        ArgumentNullException.ThrowIfNull(sample);
        _ = mode; // Quick/Deep selection has no behavioural effect in the structural slice.

        sample.Position = 0;
        var hash = await SHA256.HashDataAsync(sample, cancellationToken).ConfigureAwait(false);
        var sha256 = Convert.ToHexStringLower(hash);

        // Analyse and report the bytes actually present, never the broker's declared
        // size. A disagreement is an integrity anomaly (the sample changed under a
        // handle that should deny writes), so fail closed rather than analyse either
        // interpretation.
        var size = sample.Length;
        if (declaredSize != size)
            return PeScanResultMapper.Malformed(sha256, size);

        if (!IsPortableExecutable(sample, size))
            return PeScanResultMapper.Unsupported(sha256, size);

        try
        {
            sample.Position = 0;
            var input = new ArtifactInput("root", sample, size);
            var analysis = await (analyzer ?? new PeAnalyzer())
                .AnalyzeAsync(input, new AnalysisContext(), cancellationToken)
                .ConfigureAwait(false);
            return PeScanResultMapper.Map(analysis, sha256, size);
        }
        catch (Exception exception) when (
            exception is IOException or BadImageFormatException or ArgumentException
                or OverflowException or InvalidOperationException or IndexOutOfRangeException)
        {
            // PeFormatException derives from IOException, but the managed metadata reader
            // (System.Reflection.Metadata) and AsmResolver reject hostile bytes with a wider
            // fault set — most notably BadImageFormatException from the CLR metadata walk,
            // which is only partially guarded inside the analyzers. Every such parser
            // rejection maps to a malformed/incomplete result rather than propagating as a
            // fault that would crash the worker and be mislabelled as an isolation failure.
            // Cancellation and fatal/environmental faults are deliberately not caught here.
            return PeScanResultMapper.Malformed(sha256, size);
        }
    }

    private static bool IsPortableExecutable(Stream sample, long size)
    {
        if (size < 64) return false;

        Span<byte> header = stackalloc byte[64];
        sample.Position = 0;
        if (!TryReadExact(sample, header)) return false;
        if (header[0] != (byte)'M' || header[1] != (byte)'Z') return false;

        var peOffset = BinaryPrimitives.ReadInt32LittleEndian(header[0x3c..]);
        if (peOffset < 64 || peOffset > MaxPeHeaderOffset || peOffset > size - 4) return false;

        Span<byte> signature = stackalloc byte[4];
        sample.Position = peOffset;
        return TryReadExact(sample, signature) && signature.SequenceEqual("PE\0\0"u8);
    }

    private static bool TryReadExact(Stream stream, Span<byte> buffer)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = stream.Read(buffer[total..]);
            if (read == 0) return false;
            total += read;
        }

        return true;
    }
}
