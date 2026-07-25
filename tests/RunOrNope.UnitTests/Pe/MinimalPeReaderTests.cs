using AwesomeAssertions;
using RunOrNope.Analyzers.Pe;
using Xunit;

namespace RunOrNope.UnitTests.Pe;

public sealed class MinimalPeReaderTests
{
    [Fact]
    public void Parse_ValidSyntheticPe_ReportsSectionAndOverlay()
    {
        var bytes = PeFixture.Create(sectionRawSize: 0x200, overlay: 17);
        var result = MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        result.Sections.Should().ContainSingle();
        result.OverlayOffset.Should().Be(bytes.Length - 17);
        result.OverlayLength.Should().Be(17);
    }

    [Fact]
    public void Parse_TruncatedSection_IsRejectedWithoutReadingPastEnd()
    {
        var bytes = PeFixture.Create(sectionRawSize: 0x200);
        Array.Resize(ref bytes, bytes.Length - 1);
        var act = () => MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        act.Should().Throw<PeFormatException>().WithMessage("*section*");
    }

    [Fact]
    public void Parse_OverflowingSectionRange_IsRejected()
    {
        var bytes = PeFixture.Create();
        BitConverter.GetBytes(uint.MaxValue).CopyTo(bytes, 0x188 + 20);
        var act = () => MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        act.Should().Throw<PeFormatException>();
    }

    [Fact]
    public void Parse_CertificateOutsideFile_IsRejected()
    {
        var bytes = PeFixture.Create();
        BitConverter.GetBytes((uint)(bytes.Length - 4)).CopyTo(bytes, 0x108 + 8 * 4);
        BitConverter.GetBytes(64u).CopyTo(bytes, 0x10c + 8 * 4);
        var act = () => MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        act.Should().Throw<PeFormatException>().WithMessage("*certificate*");
    }

    [Fact]
    public void RvaToOffset_UnmappedRva_ReturnsNull()
    {
        var bytes = PeFixture.Create();
        MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken)
            .RvaToFileOffset(0x900000).Should().BeNull();
    }

    [Fact]
    public void Parse_UnmappedDataDirectory_IsRejected()
    {
        var bytes = PeFixture.Create();
        BitConverter.GetBytes(0x900000u).CopyTo(bytes, 0x108);
        BitConverter.GetBytes(16u).CopyTo(bytes, 0x10c);
        var act = () => MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        act.Should().Throw<PeFormatException>().WithMessage("*directory 0*");
    }

    [Theory]
    [InlineData(0x1f8u, 16u)]
    [InlineData(0x11f0u, 32u)]
    public void Parse_DataDirectoryCrossingOneContiguousMapping_IsRejected(uint rva, uint size)
    {
        var bytes = PeFixture.Create();
        BitConverter.GetBytes(rva).CopyTo(bytes, 0x108);
        BitConverter.GetBytes(size).CopyTo(bytes, 0x10c);
        var act = () => MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        act.Should().Throw<PeFormatException>().WithMessage("*directory 0*");
    }

    [Fact]
    public void Parse_MisalignedCertificateTable_IsRejected()
    {
        var bytes = PeFixture.Create(overlay: 16);
        BitConverter.GetBytes(0x401u).CopyTo(bytes, 0x128);
        BitConverter.GetBytes(8u).CopyTo(bytes, 0x12c);
        var act = () => MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        act.Should().Throw<PeFormatException>().WithMessage("*aligned*");
    }

    [Fact]
    public void Parse_CertificateOverlappingSection_IsRejected()
    {
        var bytes = PeFixture.Create();
        BitConverter.GetBytes(0x200u).CopyTo(bytes, 0x128);
        BitConverter.GetBytes(8u).CopyTo(bytes, 0x12c);
        var act = () => MinimalPeReader.Parse(new MemoryStream(bytes), bytes.Length, TestContext.Current.CancellationToken);
        act.Should().Throw<PeFormatException>().WithMessage("*overlaps*");
    }
}

internal static class PeFixture
{
    public static byte[] Create(int sectionRawSize = 0x200, int overlay = 0)
    {
        var bytes = new byte[0x200 + sectionRawSize + overlay];
        bytes[0] = (byte)'M'; bytes[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(bytes, 0x3c);
        bytes[0x80] = (byte)'P'; bytes[0x81] = (byte)'E';
        BitConverter.GetBytes((ushort)0x8664).CopyTo(bytes, 0x84);
        BitConverter.GetBytes((ushort)1).CopyTo(bytes, 0x86);
        BitConverter.GetBytes((ushort)0xf0).CopyTo(bytes, 0x94);
        BitConverter.GetBytes((ushort)0x20b).CopyTo(bytes, 0x98);
        BitConverter.GetBytes(0x1000u).CopyTo(bytes, 0xa8);
        BitConverter.GetBytes(0x1000u).CopyTo(bytes, 0xb0);
        BitConverter.GetBytes(0x200u).CopyTo(bytes, 0xb4);
        BitConverter.GetBytes(0x2000u).CopyTo(bytes, 0xd0);
        BitConverter.GetBytes(0x200u).CopyTo(bytes, 0xd4);
        BitConverter.GetBytes(16u).CopyTo(bytes, 0x104);
        var s = 0x188;
        bytes[s] = (byte)'.'; bytes[s + 1] = (byte)'t'; bytes[s + 2] = (byte)'e'; bytes[s + 3] = (byte)'x'; bytes[s + 4] = (byte)'t';
        BitConverter.GetBytes((uint)sectionRawSize).CopyTo(bytes, s + 8);
        BitConverter.GetBytes(0x1000u).CopyTo(bytes, s + 12);
        BitConverter.GetBytes((uint)sectionRawSize).CopyTo(bytes, s + 16);
        BitConverter.GetBytes(0x200u).CopyTo(bytes, s + 20);
        BitConverter.GetBytes(0x60000020u).CopyTo(bytes, s + 36);
        return bytes;
    }
}
