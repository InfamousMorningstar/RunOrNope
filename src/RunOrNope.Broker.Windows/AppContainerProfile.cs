using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace RunOrNope.Broker.Windows;

public sealed class AppContainerProfile : IDisposable
{
    private readonly IReadOnlyList<string> _capabilities = Array.Empty<string>();
    private bool _disposed;

    private AppContainerProfile(string name, IntPtr sid)
        => (Name, Sid) = (name, sid);

    public string Name { get; }
    internal IntPtr Sid { get; private set; }
    internal string SidString => Sid == IntPtr.Zero
        ? throw new ObjectDisposedException(nameof(AppContainerProfile))
        : new SecurityIdentifier(Sid).Value;
    public IReadOnlyList<string> Capabilities => _capabilities;

    public static string CreateUniqueName() =>
        $"RunOrNope.Worker.{Environment.ProcessId}.{Guid.NewGuid():N}";

    public static AppContainerProfile Create()
    {
        if (!OperatingSystem.IsWindows())
            throw new IsolationUnavailableException("AppContainer is available only on Windows.");

        var name = CreateUniqueName();
        var result = NativeMethods.CreateAppContainerProfile(
            name, "RunOrNope disposable worker", "Capability-free static parser",
            IntPtr.Zero, 0, out var sid);
        if (result == NativeMethods.ErrorAlreadyExists)
        {
            // A cryptographically unique collision is treated as hostile state.
            throw new IsolationUnavailableException("The unique AppContainer profile already existed.");
        }
        if (result != 0 || sid == IntPtr.Zero)
            throw new IsolationUnavailableException($"Windows could not create AppContainer profile (0x{result:X8}).");
        return new(name, sid);
    }

    internal string CreatePrivateOutputDirectory()
    {
        ObjectDisposedException.ThrowIf(Sid == IntPtr.Zero, this);
        var currentUser = WindowsIdentity.GetCurrent().User
            ?? throw new IsolationUnavailableException("The broker user SID is unavailable.");
        var worker = new SecurityIdentifier(Sid);
        var security = new DirectorySecurity();
        security.SetOwner(currentUser);
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            currentUser, FileSystemRights.FullControl, InheritanceFlags.ContainerInherit |
            InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            worker, FileSystemRights.ReadAndExecute | FileSystemRights.Write |
            FileSystemRights.DeleteSubdirectoriesAndFiles | FileSystemRights.Delete,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));

        var root = Path.Combine(Path.GetTempPath(), "RunOrNope", Guid.NewGuid().ToString("N"));
        var directory = new DirectoryInfo(root);
        directory.Create(security);
        var actual = directory.GetAccessControl();
        if (!actual.AreAccessRulesProtected)
        {
            Directory.Delete(root);
            throw new IsolationUnavailableException("The private output ACL could not be verified.");
        }
        var owner = actual.GetOwner(typeof(SecurityIdentifier));
        var rules = actual.GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        var brokerRights = FileSystemRights.FullControl;
        var workerRights = FileSystemRights.Modify | FileSystemRights.Synchronize |
                           FileSystemRights.DeleteSubdirectoriesAndFiles;
        if (!currentUser.Equals(owner) || rules.Length != 2 ||
            !HasExactRule(rules, currentUser, brokerRights) ||
            !HasExactRule(rules, worker, workerRights))
        {
            Directory.Delete(root);
            var detail = string.Join("; ", rules.Select(rule =>
                $"{rule.IdentityReference}:{rule.FileSystemRights}:{rule.InheritanceFlags}:{rule.PropagationFlags}:{rule.AccessControlType}:{rule.IsInherited}"));
            throw new IsolationUnavailableException(
                $"The private output ACL is not canonical and exact (owner={owner}; {detail}).");
        }
        return root;
    }

    private static bool HasExactRule(
        IEnumerable<FileSystemAccessRule> rules, SecurityIdentifier sid, FileSystemRights rights) =>
        rules.Any(rule =>
            rule.IdentityReference.Equals(sid) &&
            rule.AccessControlType == AccessControlType.Allow &&
            rule.FileSystemRights == rights &&
            rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) &&
            rule.PropagationFlags == PropagationFlags.None &&
            !rule.IsInherited);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (Sid != IntPtr.Zero)
        {
            NativeMethods.FreeSid(Sid);
            Sid = IntPtr.Zero;
        }
        var result = NativeMethods.DeleteAppContainerProfile(Name);
        if (result != 0 && result != NativeMethods.ErrorFileNotFound)
            throw new IsolationUnavailableException($"Windows could not delete AppContainer profile (0x{result:X8}).");
    }
}

public sealed class IsolationUnavailableException(string message, Exception? inner = null)
    : InvalidOperationException(message, inner);

public sealed record WorkerIsolationPolicy(
    IReadOnlyList<string> CapabilitySids,
    uint ActiveProcessLimit,
    bool DenyChildProcesses,
    bool KillOnJobClose,
    bool ProhibitDynamicCode,
    bool DisableExtensionPoints,
    bool RestrictRemoteAndLowIntegrityImagesPreferSystem32,
    bool RequirePrivateOutputAcl,
    long ProcessMemoryBytes,
    TimeSpan ProcessCpuTime,
    TimeSpan WallClockTimeout)
{
    public static WorkerIsolationPolicy Default { get; } = new(
        Array.Empty<string>(), 1, true, true, false, true, true, true,
        256L * 1024 * 1024, TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(45));
}
