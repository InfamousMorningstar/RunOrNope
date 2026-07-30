using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RunOrNope.Intake;

internal interface IRelativePathNative
{
    SafeFileHandle OpenRoot(string root);
    SafeFileHandle OpenRelativeDirectory(SafeFileHandle parent, string component);
    SafeFileHandle OpenRelativeFile(SafeFileHandle parent, string component);
    FileSnapshot ReadSnapshot(SafeFileHandle handle);
    string GetFinalPath(SafeFileHandle handle);
}

internal static class VerifiedPathWalker
{
    private readonly record struct DirectorySecuritySnapshot(
        FileIdentity Identity, bool IsDirectory, bool IsDeletePending, bool IsReparse)
    {
        internal static DirectorySecuritySnapshot From(FileSnapshot snapshot) =>
            new(snapshot.Identity, snapshot.IsDirectory, snapshot.IsDeletePending,
                (snapshot.Attributes & WindowsFileIdentity.FileAttributeReparsePoint) != 0);
    }

    internal static SafeFileHandle Open(string fullPath, IRelativePathNative native)
    {
        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrEmpty(root)) throw new IntakeRejectedException("A rooted local path is required.");
        var relative = Path.GetRelativePath(root, fullPath);
        var components = relative.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0) throw new IntakeRejectedException("A file path is required.");

        var heldDirectories = new List<SafeFileHandle>();
        SafeFileHandle? final = null;
        try
        {
            var current = native.OpenRoot(root);
            heldDirectories.Add(current);
            ValidateDirectory(current, native);

            for (var index = 0; index < components.Length - 1; index++)
            {
                var before = DirectorySecuritySnapshot.From(native.ReadSnapshot(current));
                var child = native.OpenRelativeDirectory(current, components[index]);
                heldDirectories.Add(child);
                var after = DirectorySecuritySnapshot.From(native.ReadSnapshot(current));
                if (before != after)
                    throw new IntakeTamperedException("An ancestor directory changed during secure path traversal.");
                ValidateDirectory(child, native);
                current = child;
            }

            var parentBefore = DirectorySecuritySnapshot.From(native.ReadSnapshot(current));
            final = native.OpenRelativeFile(current, components[^1]);
            var parentAfter = DirectorySecuritySnapshot.From(native.ReadSnapshot(current));
            if (parentBefore != parentAfter)
                throw new IntakeTamperedException("The parent directory changed while the input was opened.");
            SafeFileIntake.EnsureLocalPath(native.GetFinalPath(final));
            return final;
        }
        catch
        {
            final?.Dispose();
            throw;
        }
        finally
        {
            foreach (var directory in heldDirectories) directory.Dispose();
        }
    }

    private static void ValidateDirectory(SafeFileHandle handle, IRelativePathNative native)
    {
        var snapshot = native.ReadSnapshot(handle);
        if (!snapshot.IsDirectory || snapshot.IsDeletePending ||
            (snapshot.Attributes & WindowsFileIdentity.FileAttributeReparsePoint) != 0)
            throw new IntakeRejectedException("Every ancestor must be a stable, non-reparse local directory.");
        SafeFileIntake.EnsureLocalPath(native.GetFinalPath(handle));
    }
}

internal sealed class WindowsRelativePathNative : IRelativePathNative
{
    private const uint GenericRead = 0x80000000;
    private const uint FileReadAttributes = 0x00000080;
    private const uint Synchronize = 0x00100000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint DirectoryShare = FileShareRead | FileShareWrite | FileShareDelete;
    private const uint OpenExisting = 3;
    private const uint NtFileOpen = 1;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint ObjCaseInsensitive = 0x00000040;
    private const uint FileDirectoryFile = 0x00000001;
    private const uint FileNonDirectoryFile = 0x00000040;
    private const uint FileSynchronousIoNonAlert = 0x00000020;
    private const uint FileOpenReparsePoint = 0x00200000;

    public SafeFileHandle OpenRoot(string root)
    {
        var handle = CreateFileW(root, FileReadAttributes | Synchronize, DirectoryShare, IntPtr.Zero,
            OpenExisting, FileFlagBackupSemantics | FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid) ThrowOpenFailure("local drive root", Marshal.GetLastWin32Error());
        return handle;
    }

    public SafeFileHandle OpenRelativeDirectory(SafeFileHandle parent, string component) =>
        NtOpenRelative(parent, component, FileReadAttributes | Synchronize,
            DirectoryShare,
            FileDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint);

    public SafeFileHandle OpenRelativeFile(SafeFileHandle parent, string component) =>
        NtOpenRelative(parent, component, GenericRead, FileShareRead,
            FileNonDirectoryFile | FileSynchronousIoNonAlert | FileOpenReparsePoint);

    public FileSnapshot ReadSnapshot(SafeFileHandle handle) => WindowsFileIdentity.Read(handle);
    public string GetFinalPath(SafeFileHandle handle) => WindowsIntakeOperations.ReadFinalPath(handle);

    private static SafeFileHandle NtOpenRelative(
        SafeFileHandle parent, string component, uint desiredAccess, uint shareAccess, uint createOptions)
    {
        if (component is "." or ".." || component.Contains('\\') || component.Contains('/') ||
            component.Contains(':'))
            throw new IntakeRejectedException("Invalid path component.");

        var stringBuffer = Marshal.StringToHGlobalUni(component);
        var unicodePointer = IntPtr.Zero;
        var parentAdded = false;
        try
        {
            var unicode = new UnicodeString
            {
                Length = checked((ushort)(component.Length * 2)),
                MaximumLength = checked((ushort)((component.Length + 1) * 2)),
                Buffer = stringBuffer
            };
            unicodePointer = Marshal.AllocHGlobal(Marshal.SizeOf<UnicodeString>());
            Marshal.StructureToPtr(unicode, unicodePointer, false);
            parent.DangerousAddRef(ref parentAdded);
            var attributes = new ObjectAttributes
            {
                Length = Marshal.SizeOf<ObjectAttributes>(),
                RootDirectory = parent.DangerousGetHandle(),
                ObjectName = unicodePointer,
                Attributes = ObjCaseInsensitive
            };
            // NtCreateFile is used solely for its RootDirectory contract: the
            // component is resolved beneath the already verified/held parent
            // handle, eliminating a path check/open race. FILE_OPEN (1) never
            // creates or modifies an object; FILE_OPEN_REPARSE_POINT prevents
            // traversal of the component itself. FILE_SYNCHRONOUS_IO_NONALERT
            // makes the returned handle compatible with synchronous consumers
            // such as the isolated worker's FileStream. Without it, NtCreateFile
            // returns an asynchronous handle even though SafeFileHandle carries
            // no metadata that lets FileStream select the matching strategy.
            var status = NtCreateFile(out var handle, desiredAccess, ref attributes, out _,
                IntPtr.Zero, 0, shareAccess, NtFileOpen, createOptions, IntPtr.Zero, 0);
            if (status < 0 || handle.IsInvalid)
            {
                handle?.Dispose();
                // NTSTATUS success values are non-negative. Every negative
                // status fails closed after translation for diagnostics only.
                var win32 = RtlNtStatusToDosError(status);
                ThrowOpenFailure("relative path component", unchecked((int)win32));
            }
            return handle;
        }
        finally
        {
            if (parentAdded) parent.DangerousRelease();
            if (unicodePointer != IntPtr.Zero) Marshal.FreeHGlobal(unicodePointer);
            Marshal.FreeHGlobal(stringBuffer);
        }
    }

    [DoesNotReturn]
    private static void ThrowOpenFailure(string subject, int error) =>
        throw new IOException($"Windows could not securely open the {subject}.", new Win32Exception(error));

    [StructLayout(LayoutKind.Sequential)]
    private struct UnicodeString { public ushort Length, MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory, ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor, SecurityQualityOfService;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoStatusBlock { public IntPtr Status, Information; }

    [DllImport("ntdll.dll")]
    private static extern int NtCreateFile(out SafeFileHandle fileHandle, uint desiredAccess,
        ref ObjectAttributes objectAttributes, out IoStatusBlock ioStatusBlock,
        IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint createDisposition,
        uint createOptions, IntPtr eaBuffer, uint eaLength);
    [DllImport("ntdll.dll")]
    private static extern uint RtlNtStatusToDosError(int status);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
}
