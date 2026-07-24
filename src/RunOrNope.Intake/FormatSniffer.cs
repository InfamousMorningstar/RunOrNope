using Microsoft.Win32.SafeHandles;

namespace RunOrNope.Intake;

public enum RootFormat { PortableExecutable, CompoundFileCandidate, UnsupportedOrInvalid }

public static class FormatSniffer
{
    private const int MaxPeHeaderOffset = 1024 * 1024;
    private static ReadOnlySpan<byte> CompoundMagic => [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

    internal static async ValueTask<RootFormat> DetectAsync(
        IIntakeOperations operations, SafeFileHandle handle, long size, CancellationToken cancellationToken)
    {
        var header = new byte[512];
        var read = await ReadAtMostAsync(operations, handle, header, 0, cancellationToken).ConfigureAwait(false);
        if (read >= 8 && header.AsSpan(0, 8).SequenceEqual(CompoundMagic))
        {
            if (read < 512 || header[28] != 0xFE || header[29] != 0xFF)
                return RootFormat.UnsupportedOrInvalid;
            var sectorShift = BitConverter.ToUInt16(header, 30);
            var miniSectorShift = BitConverter.ToUInt16(header, 32);
            return sectorShift is 9 or 12 && miniSectorShift == 6
                ? RootFormat.CompoundFileCandidate
                : RootFormat.UnsupportedOrInvalid;
        }

        if (read < 64 || header[0] != (byte)'M' || header[1] != (byte)'Z')
            return RootFormat.UnsupportedOrInvalid;

        var peOffset = BitConverter.ToInt32(header, 0x3c);
        if (peOffset < 64 || peOffset > MaxPeHeaderOffset || peOffset > size - 4)
            return RootFormat.UnsupportedOrInvalid;

        var signature = new byte[4];
        read = await ReadAtMostAsync(operations, handle, signature, peOffset, cancellationToken).ConfigureAwait(false);
        return read == 4 && signature.AsSpan().SequenceEqual("PE\0\0"u8)
            ? RootFormat.PortableExecutable
            : RootFormat.UnsupportedOrInvalid;
    }

    private static async ValueTask<int> ReadAtMostAsync(
        IIntakeOperations operations, SafeFileHandle handle, Memory<byte> buffer, long offset, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await operations.ReadAsync(handle, buffer[total..], offset + total, cancellationToken)
                .ConfigureAwait(false);
            if (read == 0) break;
            total += read;
        }
        return total;
    }
}
