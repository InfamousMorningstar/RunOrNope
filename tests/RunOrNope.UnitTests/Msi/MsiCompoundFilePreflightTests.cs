using System.Buffers.Binary;
using AwesomeAssertions;
using RunOrNope.Analyzers.Msi;
using Xunit;

namespace RunOrNope.UnitTests.Msi;

public sealed class MsiCompoundFilePreflightTests
{
    private static readonly Guid MsiRootClsid = new("000C1084-0000-0000-C000-000000000046");

    [Fact]
    public void Classify_recognizes_a_valid_msi_package_root_clsid()
    {
        var result = MsiCompoundFilePreflight.Classify(ValidCfbfWith(MsiRootClsid));

        result.Disposition.Should().Be(MsiFormatDisposition.MsiPackage);
        result.IncompleteReason.Should().BeNull();
    }

    [Fact]
    public void Classify_reports_a_valid_non_msi_compound_file()
    {
        var result = MsiCompoundFilePreflight.Classify(ValidCfbfWith(Guid.Empty));

        result.Disposition.Should().Be(MsiFormatDisposition.OtherCompoundFile);
        result.IncompleteReason.Should().BeNull();
    }

    [Fact]
    public void Classify_reports_an_overflowing_difat_as_malformed()
    {
        var result = MsiCompoundFilePreflight.Classify(OverflowingDifatCfbf());

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
        result.IncompleteReason.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Classify_reports_a_truncated_header_as_malformed()
    {
        var result = MsiCompoundFilePreflight.Classify(new MemoryStream(CfbfHeader()[..511]));

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
        result.IncompleteReason.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Classify_reports_an_invalid_byte_order_as_malformed()
    {
        var bytes = ValidCfbfWith(MsiRootClsid).ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1c), 0xfeff);

        var result = MsiCompoundFilePreflight.Classify(new MemoryStream(bytes));

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
    }

    [Theory]
    [InlineData((ushort)3, (ushort)12)]
    [InlineData((ushort)4, (ushort)9)]
    [InlineData((ushort)5, (ushort)9)]
    public void Classify_reports_version_and_sector_shift_mismatches_as_malformed(ushort version, ushort sectorShift)
    {
        var bytes = ValidCfbfWith(MsiRootClsid).ToArray();
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1a), version);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1e), sectorShift);

        var result = MsiCompoundFilePreflight.Classify(new MemoryStream(bytes));

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
    }

    [Fact]
    public void Classify_reports_an_out_of_file_first_directory_sector_as_malformed()
    {
        var bytes = ValidCfbfWith(MsiRootClsid).ToArray();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x30), 10);

        var result = MsiCompoundFilePreflight.Classify(new MemoryStream(bytes));

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
    }

    [Fact]
    public void Classify_reports_a_non_root_directory_entry_as_malformed()
    {
        var bytes = ValidCfbfWith(MsiRootClsid).ToArray();
        bytes[512 + 66] = 1;

        var result = MsiCompoundFilePreflight.Classify(new MemoryStream(bytes));

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
    }

    [Fact]
    public void Classify_requires_a_readable_stream()
    {
        var action = () => MsiCompoundFilePreflight.Classify(Stream.Null);

        action.Should().NotThrow();
        MsiCompoundFilePreflight.Classify(Stream.Null).Disposition.Should().Be(MsiFormatDisposition.Malformed);
    }

    private static MemoryStream ValidCfbfWith(Guid rootClsid)
    {
        var bytes = CfbfHeader();
        rootClsid.TryWriteBytes(bytes.AsSpan(512 + 80, 16));
        bytes[512 + 66] = 5;
        return new MemoryStream(bytes, writable: false);
    }

    private static MemoryStream OverflowingDifatCfbf()
    {
        var bytes = CfbfHeader();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x48), uint.MaxValue);
        return new MemoryStream(bytes, writable: false);
    }

    private static byte[] CfbfHeader()
    {
        var bytes = new byte[1_024];
        new byte[] { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 }.CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x18), 0x003e);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1a), 3);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1c), 0xfffe);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1e), 9);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x20), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x30), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x3c), 0xfffffffe);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x44), 0xfffffffe);
        for (var offset = 0x4c; offset < 512; offset += 4)
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), 0xffffffff);
        return bytes;
    }
}
