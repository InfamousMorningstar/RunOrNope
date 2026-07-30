using System.Buffers.Binary;

namespace RunOrNope.Analyzers.Msi;

/// <summary>
/// Performs a bounded structural check of a Compound File Binary Format stream.
/// This discriminator never invokes Windows Installer or OLE storage APIs.
/// </summary>
public static class MsiCompoundFilePreflight
{
    private const int HeaderSize = 512;
    private const uint EndOfChain = 0xfffffffe;
    private const int DirectoryEntryTypeOffset = 66;
    private const int DirectoryEntryClsidOffset = 80;
    private static readonly byte[] Signature = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
    private static readonly Guid MsiRootClsid = new("000C1084-0000-0000-C000-000000000046");

    public static MsiPreflightResult Classify(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);

        try
        {
            if (!stream.CanRead || !stream.CanSeek)
                return Malformed("The compound-file stream is not readable and seekable.");
            if (stream.Length < HeaderSize) return Malformed("The compound-file header is truncated.");
            stream.Position = 0;
            var header = new byte[HeaderSize];
            if (!ReadExactly(stream, header)) return Malformed("The compound-file header is truncated.");
            if (!header.AsSpan(0, Signature.Length).SequenceEqual(Signature))
                return Malformed("The compound-file signature is invalid.");
            if (BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x1c)) != 0xfffe)
                return Malformed("The compound-file byte order is invalid.");

            var version = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x1a));
            var sectorShift = BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x1e));
            if ((version, sectorShift) is not (3, 9) and not (4, 12))
                return Malformed("The compound-file version and sector size disagree.");
            if (BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(0x20)) != 6)
                return Malformed("The compound-file mini-sector size is invalid.");
            if (version == 3 && BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x28)) != 0)
                return Malformed("A version 3 compound file declares directory sectors.");

            var sectorSize = 1 << sectorShift;
            var streamLength = stream.Length;
            if (streamLength < sectorSize)
                return Malformed("The compound-file header sector is truncated.");
            if (streamLength % sectorSize != 0)
                return Malformed("The compound-file layout ends in a partial sector.");

            var availableSectors = checked((streamLength - sectorSize) / sectorSize);
            var fatSectors = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x2c));
            var firstDirectorySector = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x30));
            var difatSectors = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x48));
            var firstDifatSector = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0x44));

            var difatEntries = checked((long)difatSectors * ((sectorSize / sizeof(uint)) - 1));
            var requiredFatEntries = checked((long)fatSectors + difatEntries);
            if (requiredFatEntries > availableSectors || difatSectors > availableSectors)
                return Malformed("The compound-file FAT or DIFAT count exceeds the stream.");
            if (difatSectors > 0 && firstDifatSector == EndOfChain)
                return Malformed("The compound-file DIFAT chain is missing.");

            if (!IsSectorInStream(firstDirectorySector, sectorSize, streamLength))
                return Malformed("The first directory sector is outside the stream.");

            var directoryOffset = SectorOffset(firstDirectorySector, sectorSize);
            stream.Position = directoryOffset;
            var directorySector = new byte[sectorSize];
            if (!ReadExactly(stream, directorySector)) return Malformed("The root directory sector is truncated.");
            var directoryEntry = directorySector.AsSpan(0, 128);
            if (directoryEntry[DirectoryEntryTypeOffset] != 5)
                return Malformed("The first directory entry is not root storage.");

            var rootClsid = new Guid(directoryEntry.Slice(DirectoryEntryClsidOffset, 16));
            return rootClsid == MsiRootClsid
                ? new MsiPreflightResult(MsiFormatDisposition.MsiPackage, null)
                : new MsiPreflightResult(MsiFormatDisposition.OtherCompoundFile, null);
        }
        catch (IOException)
        {
            return Malformed("The compound-file stream could not be read.");
        }
        catch (NotSupportedException)
        {
            return Malformed("The compound-file stream could not be read.");
        }
        catch (UnauthorizedAccessException)
        {
            return Malformed("The compound-file stream could not be read.");
        }
        catch (OverflowException)
        {
            return Malformed("The compound-file structure overflows its bounds.");
        }
    }

    private static bool IsSectorInStream(uint sectorId, int sectorSize, long streamLength)
    {
        var offset = SectorOffset(sectorId, sectorSize);
        return offset >= sectorSize && checked(offset + sectorSize) <= streamLength;
    }

    private static long SectorOffset(uint sectorId, int sectorSize) =>
        checked((checked((long)sectorId + 1)) * sectorSize);

    private static bool ReadExactly(Stream stream, Span<byte> buffer)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = stream.Read(buffer[read..]);
            if (count == 0) return false;
            read += count;
        }

        return true;
    }

    private static MsiPreflightResult Malformed(string reason) =>
        new(MsiFormatDisposition.Malformed, reason);
}
