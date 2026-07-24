using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ComponentModel;

namespace RunOrNope.Broker.Windows;

internal static class WorkerPackageStager
{
    internal static WorkerPackageLease Stage(
        string sourceRoot, string destinationRoot, WorkerPackageManifest manifest,
        SecurityIdentifier workerSid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationRoot);
        ArgumentNullException.ThrowIfNull(manifest);
        var heldFiles = new List<FileStream>();
        var stagedWriters = new List<FileStream>();
        var stagedPaths = new List<string>();
        var transferred = false;
        try
        {
            foreach (var entry in manifest.Document.Files)
            {
                var sourcePath = Path.Combine(sourceRoot, entry.Name);
                var source = new FileStream(sourcePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                    128 * 1024, FileOptions.SequentialScan);
                heldFiles.Add(source);
                if (source.Length != entry.Size ||
                    !HashMatches(source, entry.Sha256))
                    throw new IsolationUnavailableException(
                        $"Packaged worker file '{entry.Name}' failed authenticated hash verification.");
                source.Position = 0;
                var destinationPath = Path.Combine(destinationRoot, entry.Name);
                var destinationHandle = NativeMethods.CreateFileW(
                    destinationPath,
                    NativeMethods.GenericRead | NativeMethods.GenericWrite | NativeMethods.WriteDac,
                    NativeMethods.FileShareRead, IntPtr.Zero, NativeMethods.CreateNew,
                    NativeMethods.FileFlagWriteThrough, IntPtr.Zero);
                if (destinationHandle.IsInvalid)
                {
                    var error = new Win32Exception();
                    destinationHandle.Dispose();
                    throw error;
                }
                var destination = new FileStream(
                    destinationHandle, FileAccess.ReadWrite, 128 * 1024, isAsync: false);
                heldFiles.Add(destination);
                stagedWriters.Add(destination);
                stagedPaths.Add(destinationPath);
                source.CopyTo(destination);
                destination.Flush(flushToDisk: true);
                if (destination.Length != entry.Size || !HashMatches(destination, entry.Sha256))
                    throw new IsolationUnavailableException(
                        $"Staged worker file '{entry.Name}' failed post-copy verification.");
            }
            SealPackage(destinationRoot, stagedWriters, workerSid);
            foreach (var writer in stagedWriters)
            {
                writer.Dispose();
                heldFiles.Remove(writer);
            }
            // The protected read/execute-only ACL covers the transition from the
            // verified writer to these long-lived deny-write/delete handles.
            foreach (var path in stagedPaths)
                heldFiles.Add(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read));
            var lease = new WorkerPackageLease(
                Path.Combine(destinationRoot, manifest.Document.EntryPoint), heldFiles);
            transferred = true;
            return lease;
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or CryptographicException or
                Win32Exception)
        {
            throw new IsolationUnavailableException(
                $"The authenticated worker package could not be staged: {exception.Message}", exception);
        }
        finally
        {
            if (!transferred)
                foreach (var file in heldFiles) file.Dispose();
        }
    }

    private static void SealPackage(
        string root, IEnumerable<FileStream> files, SecurityIdentifier workerSid)
    {
        var brokerSid = WindowsIdentity.GetCurrent().User ??
            throw new IsolationUnavailableException("The broker SID is unavailable.");
        foreach (var file in files)
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(
                brokerSid, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                workerSid, FileSystemRights.ReadAndExecute, AccessControlType.Allow));
            file.SetAccessControl(security);
        }
        var markerSecurity = new FileSecurity();
        markerSecurity.SetOwner(brokerSid);
        markerSecurity.SetAccessRuleProtection(true, false);
        markerSecurity.AddAccessRule(new FileSystemAccessRule(
            brokerSid, FileSystemRights.Read, AccessControlType.Allow));
        new FileInfo(Path.Combine(root, WorkerResourceScavenger.ProfileMarkerName))
            .SetAccessControl(markerSecurity);
        var directorySecurity = new DirectorySecurity();
        directorySecurity.SetOwner(brokerSid);
        directorySecurity.SetAccessRuleProtection(true, false);
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        directorySecurity.AddAccessRule(new FileSystemAccessRule(
            brokerSid, FileSystemRights.ReadAndExecute, inheritance,
            PropagationFlags.None, AccessControlType.Allow));
        directorySecurity.AddAccessRule(new FileSystemAccessRule(
            workerSid, FileSystemRights.ReadAndExecute, inheritance,
            PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(root).SetAccessControl(directorySecurity);
    }

    private static bool HashMatches(Stream stream, string expected)
    {
        stream.Position = 0;
        var actual = SHA256.HashData(stream);
        var expectedBytes = Convert.FromHexString(expected);
        return expectedBytes.Length == 32 &&
               CryptographicOperations.FixedTimeEquals(actual, expectedBytes);
    }
}

internal sealed class WorkerPackageLease(string entryPoint, List<FileStream> heldFiles) : IDisposable
{
    internal string EntryPoint { get; } = entryPoint;

    public void Dispose()
    {
        foreach (var file in heldFiles) file.Dispose();
        heldFiles.Clear();
    }
}
