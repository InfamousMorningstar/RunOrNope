using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RunOrNope.Intake;

public readonly record struct FileIdentity(ulong VolumeSerialNumber, Guid FileId);

internal readonly record struct FileSnapshot(
    FileIdentity Identity,
    long Size,
    long LastWriteTime,
    uint Attributes,
    uint ReparseTag);

internal static class WindowsFileIdentity
{
    private const int FileBasicInfo = 0;
    private const int FileStandardInfo = 1;
    private const int FileAttributeTagInfo = 9;
    private const int FileIdInfo = 18;
    internal const uint FileAttributeReparsePoint = 0x400;

    internal static FileSnapshot Read(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandleEx(handle, FileIdInfo, out FileIdInfoNative id, (uint)Marshal.SizeOf<FileIdInfoNative>())
            || !GetFileInformationByHandleEx(handle, FileBasicInfo, out FileBasicInfoNative basic, (uint)Marshal.SizeOf<FileBasicInfoNative>())
            || !GetFileInformationByHandleEx(handle, FileStandardInfo, out FileStandardInfoNative standard, (uint)Marshal.SizeOf<FileStandardInfoNative>())
            || !GetFileInformationByHandleEx(handle, FileAttributeTagInfo, out FileAttributeTagInfoNative tag, (uint)Marshal.SizeOf<FileAttributeTagInfoNative>()))
        {
            throw new IntakeRejectedException($"Windows could not establish stable file identity (error {Marshal.GetLastWin32Error()}).");
        }

        return new(new(id.VolumeSerialNumber, id.FileId), standard.EndOfFile, basic.LastWriteTime, tag.FileAttributes, tag.ReparseTag);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileIdInfoNative { public ulong VolumeSerialNumber; public Guid FileId; }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileBasicInfoNative
    {
        public long CreationTime, LastAccessTime, LastWriteTime, ChangeTime;
        public uint FileAttributes;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileStandardInfoNative
    {
        public long AllocationSize, EndOfFile;
        public uint NumberOfLinks;
        [MarshalAs(UnmanagedType.U1)] public bool DeletePending;
        [MarshalAs(UnmanagedType.U1)] public bool Directory;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileAttributeTagInfoNative { public uint FileAttributes, ReparseTag; }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile, int fileInformationClass, out FileIdInfoNative information, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile, int fileInformationClass, out FileBasicInfoNative information, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile, int fileInformationClass, out FileStandardInfoNative information, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile, int fileInformationClass, out FileAttributeTagInfoNative information, uint size);
}
