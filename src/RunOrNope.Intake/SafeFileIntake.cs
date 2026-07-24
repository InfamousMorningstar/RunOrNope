using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace RunOrNope.Intake;

public sealed record IntakePolicy(long MaximumFileBytes, int HashBufferBytes = 128 * 1024)
{
    public static IntakePolicy Default { get; } = new(2L * 1024 * 1024 * 1024);
}

public class IntakeRejectedException(string message, Exception? inner = null) : IOException(message, inner);
public sealed class IntakeTamperedException(string message) : IntakeRejectedException(message);

public sealed class SafeFileLease : IDisposable
{
    private SafeFileHandle? _handle;
    private readonly IIntakeOperations _operations;

    internal SafeFileLease(IIntakeOperations operations, SafeFileHandle handle, FileIdentity identity,
        long size, string sha256, RootFormat format)
        => (_operations, _handle, Identity, Size, Sha256, Format) =
            (operations, handle, identity, size, sha256, format);

    public FileIdentity Identity { get; }
    public long Size { get; }
    public string Sha256 { get; }
    public RootFormat Format { get; }

    public ValueTask<int> ReadAsync(Memory<byte> destination, long fileOffset, CancellationToken cancellationToken)
    {
        if (fileOffset < 0 || fileOffset > Size) throw new ArgumentOutOfRangeException(nameof(fileOffset));
        if (destination.Length > Size - fileOffset) throw new ArgumentOutOfRangeException(nameof(destination));
        return _operations.ReadAsync(GetHandle(), destination, fileOffset, cancellationToken);
    }

    internal bool IsHandleClosedForTesting => _handle is null or { IsClosed: true };

    public void Dispose() => Interlocked.Exchange(ref _handle, null)?.Dispose();

    private SafeFileHandle GetHandle() => _handle is { IsClosed: false } handle
        ? handle : throw new ObjectDisposedException(nameof(SafeFileLease));
}

internal interface IIntakeOperations
{
    SafeFileHandle OpenLocalReadOnly(string path);
    uint GetFileType(SafeFileHandle handle);
    FileSnapshot ReadSnapshot(SafeFileHandle handle);
    string GetFinalPath(SafeFileHandle handle);
    ValueTask<int> ReadAsync(SafeFileHandle handle, Memory<byte> buffer, long offset, CancellationToken token);
    byte[] RentBuffer(int minimumLength);
    void ReturnBuffer(byte[] buffer);
}

public static class SafeFileIntake
{
    private static readonly IIntakeOperations Windows = new WindowsIntakeOperations();

    public static Task<SafeFileLease> OpenAsync(
        string path, IntakePolicy policy, CancellationToken cancellationToken) =>
        OpenAsync(path, policy, Windows, cancellationToken);

    internal static async Task<SafeFileLease> OpenAsync(
        string path, IntakePolicy policy, IIntakeOperations operations, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(operations);
        if (policy.MaximumFileBytes < 0 || policy.HashBufferBytes is < 4096 or > 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(policy));
        cancellationToken.ThrowIfCancellationRequested();
        EnsureLocalPath(path);

        SafeFileHandle handle;
        try { handle = operations.OpenLocalReadOnly(path); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IntakeRejectedException(
                "The input could not be opened as an exclusively stable, local, read-only disk file.", exception);
        }

        try
        {
            if (operations.GetFileType(handle) != WindowsIntakeOperations.FileTypeDisk)
                throw new IntakeRejectedException("Only ordinary local disk files are accepted.");
            EnsureLocalPath(operations.GetFinalPath(handle));

            var before = operations.ReadSnapshot(handle);
            ValidateSnapshot(before, policy);

            var format = await FormatSniffer.DetectAsync(operations, handle, before.Size, cancellationToken)
                .ConfigureAwait(false);
            var hash = await HashExactlyAsync(
                operations, handle, before.Size, policy.HashBufferBytes, cancellationToken).ConfigureAwait(false);
            var after = operations.ReadSnapshot(handle);
            ValidateSnapshot(after, policy);
            if (before != after)
                throw new IntakeTamperedException("The input changed while it was being acquired; analysis stopped.");

            return new(operations, handle, before.Identity, before.Size, hash, format);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static void ValidateSnapshot(FileSnapshot snapshot, IntakePolicy policy)
    {
        if (snapshot.IsDirectory) throw new IntakeRejectedException("Directories are not accepted.");
        if (snapshot.IsDeletePending) throw new IntakeRejectedException("Delete-pending inputs are not accepted.");
        if ((snapshot.Attributes & WindowsFileIdentity.FileAttributeReparsePoint) != 0)
            throw new IntakeRejectedException("Reparse-point inputs are not accepted.");
        if (snapshot.Size < 0 || snapshot.Size > policy.MaximumFileBytes)
            throw new IntakeRejectedException("The input size exceeds the configured intake limit.");
    }

    private static async Task<string> HashExactlyAsync(
        IIntakeOperations operations, SafeFileHandle handle, long expectedSize, int bufferSize,
        CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = operations.RentBuffer(bufferSize);
        try
        {
            long offset = 0;
            while (offset < expectedSize)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var wanted = (int)Math.Min(buffer.Length, expectedSize - offset);
                var read = await operations.ReadAsync(
                    handle, buffer.AsMemory(0, wanted), offset, cancellationToken).ConfigureAwait(false);
                if (read <= 0 || read > wanted)
                    throw new IntakeTamperedException("The input was truncated or returned an invalid read.");
                hash.AppendData(buffer, 0, read);
                offset += read;
            }
            return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }
        finally { operations.ReturnBuffer(buffer); }
    }

    internal static void EnsureLocalPath(string path)
    {
        if (path.StartsWith(@"\\", StringComparison.Ordinal) &&
            !path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase))
            throw new IntakeRejectedException("UNC and remote paths are not accepted.");
        if (path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\pipe\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\GLOBALROOT\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            throw new IntakeRejectedException("Device, UNC, and named-pipe paths are not accepted.");
        if (path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) &&
            (path.Length < 7 || !char.IsAsciiLetter(path[4]) || path[5] != ':' || path[6] != '\\'))
            throw new IntakeRejectedException("Only extended local drive paths are accepted.");

        var drivePath = path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ? path[4..] : path;
        string fullPath;
        try { fullPath = Path.GetFullPath(drivePath); }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new IntakeRejectedException("The input path is invalid.", exception);
        }

        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root) || root.StartsWith(@"\\", StringComparison.Ordinal))
            throw new IntakeRejectedException("The input locality could not be established.");
        var driveType = new DriveInfo(root).DriveType;
        if (!IsAllowedLocalDriveType(driveType))
            throw new IntakeRejectedException($"The input drive is not a local filesystem ({driveType}).");
    }

    internal static bool IsAllowedLocalDriveType(DriveType driveType) =>
        driveType is DriveType.Fixed or DriveType.Removable or DriveType.Ram;
}

internal sealed class WindowsIntakeOperations : IIntakeOperations
{
    internal const uint FileTypeDisk = 1;
    private readonly WindowsRelativePathNative _relative = new();

    public SafeFileHandle OpenLocalReadOnly(string path)
    {
        var drivePath = path.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ? path[4..] : path;
        return VerifiedPathWalker.Open(Path.GetFullPath(drivePath), _relative);
    }

    public uint GetFileType(SafeFileHandle handle) => GetFileTypeNative(handle);
    public FileSnapshot ReadSnapshot(SafeFileHandle handle) => WindowsFileIdentity.Read(handle);
    public ValueTask<int> ReadAsync(SafeFileHandle handle, Memory<byte> buffer, long offset, CancellationToken token) =>
        RandomAccess.ReadAsync(handle, buffer, offset, token);
    public byte[] RentBuffer(int minimumLength) => ArrayPool<byte>.Shared.Rent(minimumLength);
    public void ReturnBuffer(byte[] buffer) => ArrayPool<byte>.Shared.Return(buffer, clearArray: true);

    public string GetFinalPath(SafeFileHandle handle) => ReadFinalPath(handle);

    internal static string ReadFinalPath(SafeFileHandle handle)
    {
        const uint fileNameNormalized = 0;
        var required = GetFinalPathNameByHandleW(handle, null, 0, fileNameNormalized);
        if (required == 0) throw new IntakeRejectedException("Windows could not verify the final local path.");
        var buffer = new char[checked((int)required + 1)];
        var written = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, fileNameNormalized);
        if (written == 0 || written >= buffer.Length)
            throw new IntakeRejectedException("Windows could not verify the final local path.");
        return new string(buffer, 0, (int)written);
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFileType")]
    private static extern uint GetFileTypeNative(SafeFileHandle handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetFinalPathNameByHandleW(
        SafeFileHandle file, [Out] char[]? path, uint pathLength, uint flags);
}
