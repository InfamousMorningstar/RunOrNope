using AwesomeAssertions;
using RunOrNope.Intake;
using Xunit;

namespace RunOrNope.UnitTests.Intake;

public sealed class SafeFileIntakeTests
{
    [Fact]
    public async Task DetectsPeByStructureDespiteWrongExtension()
    {
        using var file = TempFile.Create(".txt", PeBytes());
        using var intake = await SafeFileIntake.OpenAsync(file.Path, new IntakePolicy(1024), TestContext.Current.CancellationToken);
        intake.Format.Should().Be(RootFormat.PortableExecutable);
        intake.Sha256.Should().HaveLength(64);
    }

    [Fact]
    public async Task DetectsMsiCompoundFileByMagic()
    {
        using var file = TempFile.Create(".exe", CompoundFileHeader());
        using var intake = await SafeFileIntake.OpenAsync(file.Path, new IntakePolicy(1024), TestContext.Current.CancellationToken);
        intake.Format.Should().Be(RootFormat.CompoundFileCandidate);
    }

    [Theory]
    [InlineData(new byte[] { 0x4D })]
    [InlineData(new byte[] { 0x4D, 0x5A, 0, 0 })]
    [InlineData(new byte[] { 0xD0, 0xCF, 0x11 })]
    [InlineData(new byte[] { 0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1 })]
    public async Task MalformedOrTruncatedMagicIsUnsupported(byte[] bytes)
    {
        using var file = TempFile.Create(".exe", bytes);
        using var intake = await SafeFileIntake.OpenAsync(file.Path, new IntakePolicy(1024), TestContext.Current.CancellationToken);
        intake.Format.Should().Be(RootFormat.UnsupportedOrInvalid);
    }

    [Fact]
    public async Task DeniesAWriterWhileLeaseIsOwned()
    {
        using var file = TempFile.Create(".exe", PeBytes());
        using var intake = await SafeFileIntake.OpenAsync(file.Path, new IntakePolicy(1024), TestContext.Current.CancellationToken);
        var open = () => File.Open(file.Path, FileMode.Open, FileAccess.Write, FileShare.ReadWrite);
        open.Should().Throw<IOException>();
    }

    [Fact]
    public async Task RejectsOversizedFile()
    {
        using var file = TempFile.Create(".bin", new byte[17]);
        var open = () => SafeFileIntake.OpenAsync(file.Path, new IntakePolicy(16), TestContext.Current.CancellationToken);
        await open.Should().ThrowAsync<IntakeRejectedException>().WithMessage("*size*");
    }

    [Fact]
    public async Task HonorsPreCancelledToken()
    {
        using var file = TempFile.Create(".bin", new byte[16]);
        var open = () => SafeFileIntake.OpenAsync(file.Path, new IntakePolicy(1024), new CancellationToken(true));
        await open.Should().ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [InlineData(@"\\.\pipe\runornope-test")]
    [InlineData(@"\\?\pipe\runornope-test")]
    [InlineData(@"\\localhost\pipe\runornope-test")]
    [InlineData(@"\\?\GLOBALROOT\Device\HarddiskVolume1\nope.exe")]
    [InlineData(@"\\.\PhysicalDrive0")]
    public async Task RejectsDeviceAndPipePaths(string path)
    {
        var open = () => SafeFileIntake.OpenAsync(path, new IntakePolicy(1024), TestContext.Current.CancellationToken);
        await open.Should().ThrowAsync<IntakeRejectedException>();
    }

    private static byte[] PeBytes()
    {
        var bytes = new byte[132];
        bytes[0] = 0x4d; bytes[1] = 0x5a;
        BitConverter.GetBytes(128).CopyTo(bytes, 0x3c);
        bytes[128] = 0x50; bytes[129] = 0x45;
        return bytes;
    }

    [Fact]
    public async Task NonMsiOleContainerIsOnlyACompoundCandidate()
    {
        using var file = TempFile.Create(".doc", CompoundFileHeader());
        using var intake = await SafeFileIntake.OpenAsync(
            file.Path, new IntakePolicy(1024), TestContext.Current.CancellationToken);
        intake.Format.Should().Be(RootFormat.CompoundFileCandidate);
    }

    [Fact]
    public async Task MalformedCompoundHeaderIsUnsupported()
    {
        var bytes = CompoundFileHeader();
        bytes[28] = 0;
        using var file = TempFile.Create(".msi", bytes);
        using var intake = await SafeFileIntake.OpenAsync(
            file.Path, new IntakePolicy(1024), TestContext.Current.CancellationToken);
        intake.Format.Should().Be(RootFormat.UnsupportedOrInvalid);
    }

    private static byte[] CompoundFileHeader()
    {
        var bytes = new byte[512];
        new byte[] { 0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1 }.CopyTo(bytes, 0);
        bytes[28] = 0xFE; bytes[29] = 0xFF;
        bytes[30] = 9; bytes[32] = 6;
        return bytes;
    }

    private sealed class TempFile : IDisposable
    {
        public string Path { get; }
        private TempFile(string path) => Path = path;
        public static TempFile Create(string extension, byte[] bytes)
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"{Guid.NewGuid():N}{extension}");
            File.WriteAllBytes(path, bytes);
            return new(path);
        }
        public void Dispose() => File.Delete(Path);
    }
}
