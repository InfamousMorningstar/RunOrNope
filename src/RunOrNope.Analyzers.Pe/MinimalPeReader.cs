using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Text;

namespace RunOrNope.Analyzers.Pe;

public static class MinimalPeReader
{
    private const int MaximumSections = 96;
    private const int MaximumDirectories = 16;

    public static PeLayout Parse(Stream stream, long declaredLength)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead || !stream.CanSeek) throw new ArgumentException("A readable, seekable bounded stream is required.", nameof(stream));
        if (declaredLength < 0 || declaredLength > stream.Length) throw new ArgumentOutOfRangeException(nameof(declaredLength));

        Span<byte> dos = stackalloc byte[64];
        ReadAt(stream, 0, dos, declaredLength, "DOS header");
        if (dos[0] != 'M' || dos[1] != 'Z') throw new PeFormatException("Invalid DOS signature.");
        var peOffset = BinaryPrimitives.ReadUInt32LittleEndian(dos[0x3c..]);
        Span<byte> coff = stackalloc byte[24];
        ReadAt(stream, peOffset, coff, declaredLength, "COFF header");
        if (!coff[..4].SequenceEqual("PE\0\0"u8)) throw new PeFormatException("Invalid PE signature.");
        var machine = BinaryPrimitives.ReadUInt16LittleEndian(coff[4..]);
        var sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(coff[6..]);
        var optionalSize = BinaryPrimitives.ReadUInt16LittleEndian(coff[20..]);
        if (sectionCount is 0 or > MaximumSections) throw new PeFormatException("Invalid section count.");
        if (optionalSize < 96 || optionalSize > 4096) throw new PeFormatException("Invalid optional header size.");

        var optional = new byte[optionalSize];
        var optionalOffset = CheckedAdd(peOffset, 24, "optional header");
        ReadAt(stream, optionalOffset, optional, declaredLength, "optional header");
        var magic = BinaryPrimitives.ReadUInt16LittleEndian(optional);
        var pe32Plus = magic == 0x20b;
        if (!pe32Plus && magic != 0x10b) throw new PeFormatException("Unknown optional header magic.");
        var minimum = pe32Plus ? 112 : 96;
        if (optional.Length < minimum) throw new PeFormatException("Truncated optional header.");
        var entry = BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(16));
        var sizeHeaders = BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(60));
        if (sizeHeaders > declaredLength) throw new PeFormatException("Headers extend outside file.");
        var directoryCountOffset = pe32Plus ? 108 : 92;
        var directoryStart = pe32Plus ? 112 : 96;
        var directoryCount = Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(optional.AsSpan(directoryCountOffset)), MaximumDirectories);
        if ((ulong)directoryStart + (ulong)directoryCount * 8 > (ulong)optional.Length)
            throw new PeFormatException("Data directories exceed optional header.");

        long? certOffset = null;
        long certLength = 0;
        var rvaDirectories = new List<(int Index, uint Rva, uint Size)>();
        for (var i = 0; i < directoryCount; i++)
        {
            if (i == 4) continue;
            var directory = optional.AsSpan(directoryStart + i * 8, 8);
            var rva = BinaryPrimitives.ReadUInt32LittleEndian(directory);
            var size = BinaryPrimitives.ReadUInt32LittleEndian(directory[4..]);
            if ((rva == 0) != (size == 0)) throw new PeFormatException($"Invalid data directory {i}.");
            if (rva != 0) rvaDirectories.Add((i, rva, size));
        }
        if (directoryCount > 4)
        {
            var cert = optional.AsSpan(directoryStart + 32, 8);
            var offset = BinaryPrimitives.ReadUInt32LittleEndian(cert);
            var length = BinaryPrimitives.ReadUInt32LittleEndian(cert[4..]);
            if (offset != 0 || length != 0)
            {
                if (offset == 0 || length < 8 || !Fits(offset, length, declaredLength))
                    throw new PeFormatException("Invalid certificate table range.");
                certOffset = offset;
                certLength = length;
            }
        }

        var sectionTable = CheckedAdd(optionalOffset, optionalSize, "section table");
        var sectionTableEnd = CheckedAdd(sectionTable, checked(sectionCount * 40L), "section table");
        if (sectionTableEnd > sizeHeaders || sectionTableEnd > declaredLength)
            throw new PeFormatException("Section table exceeds declared headers.");
        var sections = ImmutableArray.CreateBuilder<PeSection>(sectionCount);
        var anomalies = ImmutableArray.CreateBuilder<string>();
        long imageEnd = sizeHeaders;
        Span<byte> header = stackalloc byte[40];
        for (var i = 0; i < sectionCount; i++)
        {
            header.Clear();
            ReadAt(stream, CheckedAdd(sectionTable, checked(i * 40L), "section header"), header, declaredLength, "section header");
            var nameLength = header[..8].IndexOf((byte)0);
            if (nameLength < 0) nameLength = 8;
            var name = Encoding.ASCII.GetString(header[..nameLength]);
            var virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(header[8..]);
            var virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(header[12..]);
            var rawSize = BinaryPrimitives.ReadUInt32LittleEndian(header[16..]);
            var rawOffset = BinaryPrimitives.ReadUInt32LittleEndian(header[20..]);
            var characteristics = BinaryPrimitives.ReadUInt32LittleEndian(header[36..]);
            if (rawSize > 0 && !Fits(rawOffset, rawSize, declaredLength))
                throw new PeFormatException($"Invalid section '{name}' raw range.");
            imageEnd = Math.Max(imageEnd, checked((long)rawOffset + rawSize));
            sections.Add(new(name, virtualAddress, virtualSize, rawOffset, rawSize, characteristics));
        }

        var frozenSections = sections.ToImmutable();
        foreach (var directory in rvaDirectories)
        {
            var lastRva = CheckedLastRva(directory.Rva, directory.Size, directory.Index);
            if (MapRva(directory.Rva, sizeHeaders, frozenSections) is null
                || MapRva(lastRva, sizeHeaders, frozenSections) is null)
                throw new PeFormatException($"Data directory {directory.Index} is not backed by file bytes.");
        }
        for (var left = 0; left < frozenSections.Length; left++)
        {
            for (var right = left + 1; right < frozenSections.Length; right++)
            {
                if (RangesOverlap(frozenSections[left].RawOffset, frozenSections[left].RawSize,
                    frozenSections[right].RawOffset, frozenSections[right].RawSize))
                    anomalies.Add($"Sections {frozenSections[left].Name} and {frozenSections[right].Name} overlap in file data.");
            }
        }
        if (entry != 0)
        {
            var entrySection = frozenSections.FirstOrDefault(section =>
                entry >= section.VirtualAddress
                && (ulong)entry < (ulong)section.VirtualAddress + Math.Max(section.VirtualSize, section.RawSize));
            if (entrySection is null)
                anomalies.Add("Entry point is not mapped by a section.");
            else if ((entrySection.Characteristics & 0x20000000) == 0)
                anomalies.Add("Entry point is outside an executable section.");
        }
        var occupiedEnd = Math.Max(imageEnd, certOffset is null ? 0 : checked(certOffset.Value + certLength));
        return new(pe32Plus, machine, entry, sizeHeaders, frozenSections, certOffset, certLength,
            occupiedEnd, declaredLength - occupiedEnd, anomalies.ToImmutable());
    }

    private static bool Fits(uint offset, uint length, long fileLength) =>
        (ulong)offset + length <= (ulong)fileLength;

    private static long? MapRva(uint rva, uint sizeOfHeaders, ImmutableArray<PeSection> sections)
    {
        if (rva < sizeOfHeaders) return rva;
        foreach (var section in sections)
        {
            var span = Math.Max(section.VirtualSize, section.RawSize);
            if (rva >= section.VirtualAddress && (ulong)rva < (ulong)section.VirtualAddress + span)
            {
                var delta = rva - section.VirtualAddress;
                return delta < section.RawSize ? checked((long)section.RawOffset + delta) : null;
            }
        }
        return null;
    }

    private static bool RangesOverlap(uint offset1, uint length1, uint offset2, uint length2) =>
        length1 != 0 && length2 != 0
        && (ulong)offset1 < (ulong)offset2 + length2
        && (ulong)offset2 < (ulong)offset1 + length1;

    private static uint CheckedLastRva(uint rva, uint size, int index)
    {
        var end = (ulong)rva + size - 1;
        if (end > uint.MaxValue) throw new PeFormatException($"Data directory {index} RVA overflows.");
        return (uint)end;
    }

    private static long CheckedAdd(long left, long right, string region)
    {
        try { return checked(left + right); }
        catch (OverflowException exception) { throw new PeFormatException($"Overflow in {region}.", exception); }
    }

    private static void ReadAt(Stream stream, long offset, Span<byte> destination, long limit, string region)
    {
        if (offset < 0 || destination.Length > limit || offset > limit - destination.Length)
            throw new PeFormatException($"Truncated {region}.");
        stream.Position = offset;
        var read = 0;
        while (read < destination.Length)
        {
            var count = stream.Read(destination[read..]);
            if (count == 0) throw new PeFormatException($"Truncated {region}.");
            read += count;
        }
    }
}
