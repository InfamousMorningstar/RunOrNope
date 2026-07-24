using Microsoft.Win32.SafeHandles;
using RunOrNope.Intake;
using Xunit;

namespace RunOrNope.UnitTests.Intake;

public sealed class IntakeFailurePathTests
{
    [Theory]
    [InlineData(DriveType.Network)]
    [InlineData(DriveType.Unknown)]
    [InlineData(DriveType.NoRootDirectory)]
    [InlineData(DriveType.CDRom)]
    public void RemoteOrUnknownDriveTypesFailClosed(DriveType type) =>
        Assert.False(SafeFileIntake.IsAllowedLocalDriveType(type));

    [Theory]
    [InlineData(@"\\server\share\sample.exe")]
    [InlineData(@"\\?\UNC\server\share\sample.exe")]
    [InlineData(@"\\?\UNC\server\pipe\sample")]
    public async Task UncFormsAreRejectedBeforeOpen(string path)
    {
        var operations = new ScriptedOperations();
        await Assert.ThrowsAsync<IntakeRejectedException>(() => SafeFileIntake.OpenAsync(
            path, new IntakePolicy(1024), operations, TestContext.Current.CancellationToken));
        Assert.Equal(0, operations.OpenCount);
    }

    [Fact]
    public async Task PostOpenFinalUncPathFailsClosedAndDisposesHandle()
    {
        using var file = TestFile.Create(new byte[128]);
        var operations = new ScriptedOperations { FinalPath = @"\\?\UNC\server\share\sample.exe" };
        await Assert.ThrowsAsync<IntakeRejectedException>(() => SafeFileIntake.OpenAsync(
            file.Path, new IntakePolicy(1024), operations, TestContext.Current.CancellationToken));
        Assert.True(operations.OpenedHandle!.IsClosed);
    }

    [Fact]
    public async Task DeletePendingSnapshotFailsClosedAndDisposesHandle()
    {
        using var file = TestFile.Create(new byte[128]);
        var operations = new ScriptedOperations
        {
            SnapshotTransform = snapshot => snapshot with { IsDeletePending = true }
        };
        await Assert.ThrowsAsync<IntakeRejectedException>(() => SafeFileIntake.OpenAsync(
            file.Path, new IntakePolicy(1024), operations, TestContext.Current.CancellationToken));
        Assert.True(operations.OpenedHandle!.IsClosed);
    }

    [Theory]
    [InlineData("growth")]
    [InlineData("truncation")]
    [InlineData("metadata")]
    public async Task MutationBetweenSnapshotsFailsClosed(string mutation)
    {
        using var file = TestFile.Create(PeBytes(8192));
        var operations = new ScriptedOperations();
        operations.SnapshotTransform = snapshot =>
        {
            if (operations.SnapshotCount != 2) return snapshot;
            return mutation switch
            {
                "growth" => snapshot with { Size = snapshot.Size + 1 },
                "truncation" => snapshot with { Size = snapshot.Size - 1 },
                _ => snapshot with { LastWriteTime = snapshot.LastWriteTime + 1 }
            };
        };

        await Assert.ThrowsAsync<IntakeTamperedException>(() => SafeFileIntake.OpenAsync(
            file.Path, new IntakePolicy(16384), operations, TestContext.Current.CancellationToken));
        Assert.True(operations.OpenedHandle!.IsClosed);
        Assert.Equal(operations.BufferRentCount, operations.BufferReturnCount);
    }

    [Fact]
    public async Task EarlyZeroByteReadFailsClosedAndDisposesHandle()
    {
        using var file = TestFile.Create(PeBytes(8192));
        var operations = new ScriptedOperations { ReturnZeroOnHashStart = true };
        await Assert.ThrowsAsync<IntakeTamperedException>(() => SafeFileIntake.OpenAsync(
            file.Path, new IntakePolicy(16384), operations, TestContext.Current.CancellationToken));
        Assert.True(operations.OpenedHandle!.IsClosed);
        Assert.Equal(operations.BufferRentCount, operations.BufferReturnCount);
    }

    [Fact]
    public async Task InFlightCancellationDisposesHandle()
    {
        using var file = TestFile.Create(PeBytes(8192));
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        var operations = new ScriptedOperations { CancelOnHashStart = cancellation };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => SafeFileIntake.OpenAsync(
            file.Path, new IntakePolicy(16384), operations, cancellation.Token));
        Assert.True(operations.OpenedHandle!.IsClosed);
        Assert.Equal(operations.BufferRentCount, operations.BufferReturnCount);
    }

    [Fact]
    public async Task LeaseOwnsHandleAndRejectsReadsAfterDispose()
    {
        using var file = TestFile.Create(PeBytes(8192));
        var operations = new ScriptedOperations();
        var lease = await SafeFileIntake.OpenAsync(
            file.Path, new IntakePolicy(16384), operations, TestContext.Current.CancellationToken);
        Assert.False(operations.OpenedHandle!.IsClosed);
        lease.Dispose();
        Assert.True(operations.OpenedHandle.IsClosed);
        await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
            await lease.ReadAsync(new byte[1], 0, TestContext.Current.CancellationToken));
    }

    private sealed class ScriptedOperations : IIntakeOperations
    {
        private readonly WindowsIntakeOperations _inner = new();
        public int OpenCount { get; private set; }
        public int SnapshotCount { get; private set; }
        public SafeFileHandle? OpenedHandle { get; private set; }
        public string? FinalPath { get; init; }
        public Func<FileSnapshot, FileSnapshot>? SnapshotTransform { get; set; }
        public bool ReturnZeroOnHashStart { get; init; }
        public CancellationTokenSource? CancelOnHashStart { get; init; }
        public int BufferRentCount { get; private set; }
        public int BufferReturnCount { get; private set; }
        private int _zeroOffsetReads;

        public SafeFileHandle OpenLocalReadOnly(string path)
        {
            OpenCount++;
            return OpenedHandle = _inner.OpenLocalReadOnly(path);
        }
        public uint GetFileType(SafeFileHandle handle) => _inner.GetFileType(handle);
        public string GetFinalPath(SafeFileHandle handle) => FinalPath ?? _inner.GetFinalPath(handle);
        public FileSnapshot ReadSnapshot(SafeFileHandle handle)
        {
            SnapshotCount++;
            var snapshot = _inner.ReadSnapshot(handle);
            return SnapshotTransform?.Invoke(snapshot) ?? snapshot;
        }
        public ValueTask<int> ReadAsync(SafeFileHandle handle, Memory<byte> buffer, long offset, CancellationToken token)
        {
            if (offset == 0 && ++_zeroOffsetReads == 2)
            {
                if (ReturnZeroOnHashStart) return ValueTask.FromResult(0);
                if (CancelOnHashStart is { } source)
                {
                    source.Cancel();
                    return ValueTask.FromCanceled<int>(source.Token);
                }
            }
            return _inner.ReadAsync(handle, buffer, offset, token);
        }
        public byte[] RentBuffer(int minimumLength)
        {
            BufferRentCount++;
            return _inner.RentBuffer(minimumLength);
        }
        public void ReturnBuffer(byte[] buffer)
        {
            BufferReturnCount++;
            _inner.ReturnBuffer(buffer);
        }
    }

    private sealed class TestFile : IDisposable
    {
        public string Path { get; }
        private TestFile(string path) => Path = path;
        public static TestFile Create(byte[] bytes)
        {
            var path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            File.WriteAllBytes(path, bytes);
            return new(path);
        }
        public void Dispose() { if (File.Exists(Path)) File.Delete(Path); }
    }

    private static byte[] PeBytes(int size)
    {
        var bytes = new byte[size];
        bytes[0] = 0x4d; bytes[1] = 0x5a;
        BitConverter.GetBytes(128).CopyTo(bytes, 0x3c);
        bytes[128] = 0x50; bytes[129] = 0x45;
        return bytes;
    }
}
