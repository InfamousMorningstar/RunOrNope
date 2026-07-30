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
    public void Classify_rejects_a_v3_partial_sector_layout()
    {
        var bytes = ValidCfbfBytes(MsiRootClsid);
        Array.Resize(ref bytes, bytes.Length + 1);

        var result = MsiCompoundFilePreflight.Classify(new MemoryStream(bytes, writable: false));

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
        result.IncompleteReason.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Classify_rejects_a_v4_partial_sector_layout()
    {
        var bytes = ValidCfbfBytes(MsiRootClsid, version: 4);
        Array.Resize(ref bytes, bytes.Length + 1);

        var result = MsiCompoundFilePreflight.Classify(new MemoryStream(bytes, writable: false));

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
        result.IncompleteReason.Should().NotBeNullOrWhiteSpace();
    }

    [Fact]
    public void Classify_rejects_a_non_seekable_stream_without_reading_it()
    {
        var stream = new NonSeekableStream(ValidCfbfBytes(MsiRootClsid));

        var result = MsiCompoundFilePreflight.Classify(stream);

        result.Disposition.Should().Be(MsiFormatDisposition.Malformed);
        result.IncompleteReason.Should().NotBeNullOrWhiteSpace();
        stream.ReadAttempts.Should().Be(0);
    }

    [Fact]
    public void Classify_rejects_short_reads_before_a_claimed_complete_directory_sector()
    {
        var complete = ValidCfbfBytes(MsiRootClsid);
        var stream = new ClaimedLengthStream(complete[..640], complete.Length, maxBytesPerRead: 7);

        MsiPreflightResult? result = null;
        var action = () => result = MsiCompoundFilePreflight.Classify(stream);

        action.Should().NotThrow();
        result!.Disposition.Should().Be(MsiFormatDisposition.Malformed);
        stream.ReadAttempts.Should().BeLessThanOrEqualTo(100);
    }

    [Theory]
    [MemberData(nameof(HostileStreamFaults))]
    public void Classify_converts_hostile_stream_access_faults_to_bounded_malformed_results(
        StreamFaultPoint faultPoint,
        Exception fault)
    {
        var stream = new FaultingStream(faultPoint, fault);

        MsiPreflightResult? result = null;
        var action = () => result = MsiCompoundFilePreflight.Classify(stream);

        action.Should().NotThrow();
        result!.Disposition.Should().Be(MsiFormatDisposition.Malformed);
        result.IncompleteReason.Should().NotBeNullOrWhiteSpace();
        result.IncompleteReason!.Length.Should().BeLessThanOrEqualTo(128);
    }

    private static MemoryStream ValidCfbfWith(Guid rootClsid)
    {
        return new MemoryStream(ValidCfbfBytes(rootClsid), writable: false);
    }

    private static MemoryStream OverflowingDifatCfbf()
    {
        var bytes = CfbfHeader();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x48), uint.MaxValue);
        return new MemoryStream(bytes, writable: false);
    }

    public static IEnumerable<object[]> HostileStreamFaults()
    {
        yield return [StreamFaultPoint.Length, new IOException("fixture length fault")];
        yield return [StreamFaultPoint.Position, new NotSupportedException("fixture position fault")];
        yield return [StreamFaultPoint.Read, new UnauthorizedAccessException("fixture read fault")];
        yield return [StreamFaultPoint.Position, new OverflowException("fixture position fault")];
    }

    private static byte[] ValidCfbfBytes(Guid rootClsid, ushort version = 3)
    {
        var sectorSize = version == 4 ? 4_096 : 512;
        var bytes = CfbfHeader(version, sectorSize);
        rootClsid.TryWriteBytes(bytes.AsSpan(sectorSize + 80, 16));
        bytes[sectorSize + 66] = 5;
        return bytes;
    }

    private static byte[] CfbfHeader(ushort version = 3, int sectorSize = 512)
    {
        var bytes = new byte[checked(sectorSize * 2)];
        new byte[] { 0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1 }.CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x18), 0x003e);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1a), version);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1c), 0xfffe);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x1e), version == 4 ? (ushort)12 : (ushort)9);
        BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(0x20), 6);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x28), version == 4 ? 1u : 0u);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x30), 0);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x3c), 0xfffffffe);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(0x44), 0xfffffffe);
        for (var offset = 0x4c; offset < 512; offset += 4)
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), 0xffffffff);
        return bytes;
    }

    public enum StreamFaultPoint
    {
        Length,
        Position,
        Read,
    }

    private sealed class NonSeekableStream(byte[] bytes) : Stream
    {
        private readonly MemoryStream _inner = new(bytes, writable: false);

        public int ReadAttempts { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count)
        {
            ReadAttempts++;
            return _inner.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class ClaimedLengthStream(byte[] bytes, long claimedLength, int maxBytesPerRead) : Stream
    {
        private long _position;

        public int ReadAttempts { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => claimedLength;
        public override long Position { get => _position; set => _position = value; }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            ReadAttempts++;
            if (_position >= bytes.Length) return 0;
            var available = checked(bytes.Length - (int)_position);
            var read = Math.Min(Math.Min(buffer.Length, maxBytesPerRead), available);
            bytes.AsSpan((int)_position, read).CopyTo(buffer);
            _position += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private sealed class FaultingStream(StreamFaultPoint faultPoint, Exception fault) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length => faultPoint == StreamFaultPoint.Length ? throw fault : 1_024;
        public override long Position
        {
            get => 0;
            set
            {
                if (faultPoint == StreamFaultPoint.Position) throw fault;
            }
        }

        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (faultPoint == StreamFaultPoint.Read) throw fault;
            return 0;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
