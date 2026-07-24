using System.Buffers;
using System.ComponentModel;
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
    internal SafeFileLease(SafeFileHandle handle, FileIdentity identity, long size, string sha256, RootFormat format)
        => (_handle, Identity, Size, Sha256, Format) = (handle, identity, size, sha256, format);

    public SafeFileHandle Handle => _handle is { IsClosed: false } handle
        ? handle : throw new ObjectDisposedException(nameof(SafeFileLease));
    public FileIdentity Identity { get; }
    public long Size { get; }
    public string Sha256 { get; }
    public RootFormat Format { get; }
    public void Dispose() => Interlocked.Exchange(ref _handle, null)?.Dispose();
}

public static class SafeFileIntake
{
    public static async Task<SafeFileLease> OpenAsync(
        string path, IntakePolicy policy, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.MaximumFileBytes < 0 || policy.HashBufferBytes is < 4096 or > 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(policy));
        cancellationToken.ThrowIfCancellationRequested();
        RejectNonFilesystemSyntax(path);

        SafeFileHandle handle;
        try
        {
            handle = CreateFileW(path, 0x80000000, 0x00000001, IntPtr.Zero, 3,
                0x40000000 | 0x10000000 | 0x00200000, IntPtr.Zero);
            if (handle.IsInvalid)
                throw new IOException("CreateFileW failed.", new Win32Exception(Marshal.GetLastWin32Error()));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new IntakeRejectedException("The input could not be opened as an exclusively stable read-only disk file.", exception);
        }

        try
        {
            if (GetFileType(handle) != 1)
                throw new IntakeRejectedException("Only ordinary disk files are accepted.");

            var before = WindowsFileIdentity.Read(handle);
            if ((before.Attributes & WindowsFileIdentity.FileAttributeReparsePoint) != 0)
                throw new IntakeRejectedException("Reparse-point inputs are not accepted.");
            if (before.Size < 0 || before.Size > policy.MaximumFileBytes)
                throw new IntakeRejectedException("The input size exceeds the configured intake limit.");

            var format = await FormatSniffer.DetectAsync(handle, before.Size, cancellationToken).ConfigureAwait(false);
            var hash = await HashExactlyAsync(handle, before.Size, policy.HashBufferBytes, cancellationToken)
                .ConfigureAwait(false);
            var after = WindowsFileIdentity.Read(handle);
            if (before.Identity != after.Identity || before.Size != after.Size ||
                before.LastWriteTime != after.LastWriteTime || before.Attributes != after.Attributes ||
                before.ReparseTag != after.ReparseTag)
            {
                throw new IntakeTamperedException("The input changed while it was being acquired; analysis stopped.");
            }

            return new(handle, before.Identity, before.Size, hash, format);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    private static async Task<string> HashExactlyAsync(
        SafeFileHandle handle, long expectedSize, int bufferSize, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            long offset = 0;
            while (offset < expectedSize)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var wanted = (int)Math.Min(buffer.Length, expectedSize - offset);
                var read = await RandomAccess.ReadAsync(handle, buffer.AsMemory(0, wanted), offset, cancellationToken)
                    .ConfigureAwait(false);
                if (read == 0)
                    throw new IntakeTamperedException("The input was truncated while it was being acquired.");
                hash.AppendData(buffer, 0, read);
                offset += read;
            }
            return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }
        finally { ArrayPool<byte>.Shared.Return(buffer, clearArray: true); }
    }

    private static void RejectNonFilesystemSyntax(string path)
    {
        if (path.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\pipe\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\\?\GLOBALROOT\", StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase) ||
            IsUncNamedPipe(path))
            throw new IntakeRejectedException("Device and named-pipe paths are not accepted.");
    }

    private static bool IsUncNamedPipe(string path)
    {
        if (!path.StartsWith(@"\\", StringComparison.Ordinal)) return false;
        var serverEnd = path.IndexOf('\\', 2);
        return serverEnd >= 0 &&
            path.AsSpan(serverEnd).StartsWith(@"\pipe\", StringComparison.OrdinalIgnoreCase);
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern uint GetFileType(SafeFileHandle handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(
        string fileName, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
}
