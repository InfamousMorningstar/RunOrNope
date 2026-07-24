using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RunOrNope.Analyzers.Pe;

public interface IAuthenticodeTrustBackend
{
    ValueTask<AuthenticodeResult> VerifyAsync(
        Stream stream,
        AuthenticodePolicy policy,
        CancellationToken cancellationToken);
}

public sealed class AuthenticodeVerifier(IAuthenticodeTrustBackend backend)
{
    public async ValueTask<AuthenticodeResult> VerifyAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var layout = MinimalPeReader.Parse(stream, stream.Length);
        var certificates = ValidateCertificateTable(stream, layout);
        stream.Position = 0;
        var result = await backend.VerifyAsync(stream, new AuthenticodePolicy(), cancellationToken).ConfigureAwait(false);
        return result with { SignatureCount = certificates.Length };
    }

    public static ImmutableArray<(ushort Revision, ushort CertificateType, int Length)> ValidateCertificateTable(
        Stream stream,
        PeLayout layout)
    {
        if (layout.CertificateOffset is null) return [];
        var results = ImmutableArray.CreateBuilder<(ushort, ushort, int)>();
        var cursor = layout.CertificateOffset.Value;
        var end = checked(cursor + layout.CertificateLength);
        Span<byte> header = stackalloc byte[8];
        Span<byte> padding = stackalloc byte[7];
        while (cursor < end)
        {
            if (end - cursor < 8) throw new PeFormatException("Malformed Authenticode certificate header.");
            ReadExact(stream, cursor, header);
            var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
            if (length < 8 || length > int.MaxValue || cursor > end - length)
                throw new PeFormatException("Malformed Authenticode certificate length.");
            results.Add((BinaryPrimitives.ReadUInt16LittleEndian(header[4..]),
                BinaryPrimitives.ReadUInt16LittleEndian(header[6..]), (int)length));
            var aligned = checked(((long)length + 7) & ~7L);
            if (cursor > end - aligned) throw new PeFormatException("Malformed Authenticode padding.");
            var paddingLength = (int)(aligned - length);
            if (paddingLength > 0)
            {
                padding.Clear();
                ReadExact(stream, cursor + length, padding[..paddingLength]);
                if (padding[..paddingLength].ContainsAnyExcept((byte)0))
                    throw new PeFormatException("Non-zero Authenticode padding rejected by strict policy.");
            }
            cursor += aligned;
        }
        if (cursor != end) throw new PeFormatException("Malformed Authenticode certificate table alignment.");
        return results.ToImmutable();
    }

    private static void ReadExact(Stream stream, long offset, Span<byte> buffer)
    {
        stream.Position = offset;
        var read = 0;
        while (read < buffer.Length)
        {
            var count = stream.Read(buffer[read..]);
            if (count == 0) throw new PeFormatException("Truncated Authenticode certificate table.");
            read += count;
        }
    }
}

public sealed class PlatformUnavailableTrustBackend : IAuthenticodeTrustBackend
{
    public ValueTask<AuthenticodeResult> VerifyAsync(
        Stream stream,
        AuthenticodePolicy policy,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(new AuthenticodeResult(
            0, TrustDisposition.PlatformUnavailable, true, null, null));
    }
}

/// <summary>
/// Invokes Windows' generic Authenticode policy against an already-open file handle.
/// It never supplies a path and explicitly disables URL retrieval.
/// </summary>
public sealed class WindowsAuthenticodeTrustBackend : IAuthenticodeTrustBackend
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdSaferFlag = 0x100;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;
    private const uint WtdDisableMd2Md4 = 0x2000;
    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int CryptERevocationOffline = unchecked((int)0x80092013);
    private const int CertERevocationFailure = unchecked((int)0x800B010E);
    private static readonly Guid GenericVerifyV2 =
        new(0x00AAC56B, 0xCD44, 0x11D0, 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE);

    public ValueTask<AuthenticodeResult> VerifyAsync(
        Stream stream,
        AuthenticodePolicy policy,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!OperatingSystem.IsWindows() || stream is not FileStream fileStream)
            return ValueTask.FromResult(new AuthenticodeResult(
                0, TrustDisposition.PlatformUnavailable, true, null, null));
        if (!policy.CacheOnly || !policy.NetworkRetrievalDisabled || !policy.NonInteractive)
            throw new ArgumentException("The native backend only accepts offline, noninteractive policy.", nameof(policy));

        var safeHandle = fileStream.SafeFileHandle;
        var addedReference = false;
        IntPtr fileInfoPointer = IntPtr.Zero;
        try
        {
            safeHandle.DangerousAddRef(ref addedReference);
            var fileInfo = new WinTrustFileInfo
            {
                StructSize = checked((uint)Marshal.SizeOf<WinTrustFileInfo>()),
                FileHandle = safeHandle.DangerousGetHandle(),
            };
            fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            var trustData = CreateTrustData(fileInfoPointer, WtdStateActionVerify);
            var action = GenericVerifyV2;
            var status = WinVerifyTrust(new IntPtr(-1), ref action, ref trustData);
            var state = trustData.StateData;
            if (state != IntPtr.Zero)
            {
                trustData.StateAction = WtdStateActionClose;
                _ = WinVerifyTrust(new IntPtr(-1), ref action, ref trustData);
            }
            return ValueTask.FromResult(MapStatus(status));
        }
        finally
        {
            if (fileInfoPointer != IntPtr.Zero) Marshal.FreeHGlobal(fileInfoPointer);
            if (addedReference) safeHandle.DangerousRelease();
        }
    }

    private static WinTrustData CreateTrustData(IntPtr fileInfo, uint stateAction) => new()
    {
        StructSize = checked((uint)Marshal.SizeOf<WinTrustData>()),
        UiChoice = WtdUiNone,
        RevocationChecks = WtdRevokeNone,
        UnionChoice = WtdChoiceFile,
        FileInfo = fileInfo,
        StateAction = stateAction,
        ProviderFlags = WtdSaferFlag | WtdCacheOnlyUrlRetrieval | WtdDisableMd2Md4,
    };

    private static AuthenticodeResult MapStatus(int status)
    {
        var disposition = status switch
        {
            0 => TrustDisposition.Trusted,
            TrustENoSignature => TrustDisposition.NoSignature,
            CryptERevocationOffline or CertERevocationFailure => TrustDisposition.IndeterminateOffline,
            _ => TrustDisposition.Untrusted,
        };
        return new(status, disposition,
            disposition == TrustDisposition.IndeterminateOffline, null, "embedded-file-handle");
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = false)]
    private static extern int WinVerifyTrust(
        IntPtr windowHandle,
        ref Guid actionId,
        ref WinTrustData trustData);
}
