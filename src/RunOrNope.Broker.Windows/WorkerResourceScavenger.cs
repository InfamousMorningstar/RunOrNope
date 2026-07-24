using System.Security.AccessControl;
using System.Security.Principal;

namespace RunOrNope.Broker.Windows;

internal static class WorkerResourceScavenger
{
    internal const string ProfileMarkerName = ".runornope-profile";
    private static readonly TimeSpan MinimumAge = TimeSpan.FromHours(24);

    internal static void ScavengeDefault() =>
        Scavenge(Path.Combine(Path.GetTempPath(), "RunOrNope"), DateTime.UtcNow);

    internal static void Scavenge(string root, DateTime utcNow)
    {
        if (!Directory.Exists(root)) return;
        var currentUser = WindowsIdentity.GetCurrent().User;
        if (currentUser is null) return;

        foreach (var path in Directory.EnumerateDirectories(root))
        {
            try
            {
                var directory = new DirectoryInfo(path);
                var name = directory.Name;
                var isPackage = name.StartsWith("package-", StringComparison.Ordinal) &&
                                IsSuffixGuid(name, "package-");
                var isOutput = name.StartsWith("output-", StringComparison.Ordinal) &&
                               IsSuffixGuid(name, "output-");
                if ((directory.Attributes & FileAttributes.ReparsePoint) != 0 ||
                    utcNow - directory.LastWriteTimeUtc < MinimumAge ||
                    (!isPackage && !isOutput) ||
                    !IsOwnedProtectedPrivateDirectory(directory, currentUser, isPackage))
                    continue;
                if (isPackage)
                {
                    var marker = Path.Combine(path, ProfileMarkerName);
                    if (!File.Exists(marker)) continue;
                    var profile = File.ReadAllText(marker);
                    if (!IsRunOrNopeProfileName(profile)) continue;
                    var deletion = NativeMethods.DeleteAppContainerProfile(profile);
                    if (deletion != 0 && deletion != NativeMethods.ErrorFileNotFound) continue;
                    directory.Delete(recursive: true);
                }
                else if (isOutput)
                {
                    directory.Delete(recursive: true);
                }
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or
                    System.Security.SecurityException)
            {
                // Bounded best effort. A future launch retries only resources
                // that still satisfy every ownership/name/age guard.
            }
        }
    }

    private static bool IsOwnedProtectedPrivateDirectory(
        DirectoryInfo directory, SecurityIdentifier currentUser, bool allowAppContainerOwner)
    {
        var security = directory.GetAccessControl(
            AccessControlSections.Owner | AccessControlSections.Access);
        if (security.GetOwner(typeof(SecurityIdentifier)) is not SecurityIdentifier owner)
            return false;
        if (!security.AreAccessRulesProtected)
            return false;
        var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>().ToArray();
        var appContainer = rules.SingleOrDefault(rule => rule.IdentityReference.Value.StartsWith(
            "S-1-15-2-", StringComparison.Ordinal))?.IdentityReference as SecurityIdentifier;
        var ownerIsExpected = currentUser.Equals(owner) ||
                              (allowAppContainerOwner && appContainer?.Equals(owner) == true);
        return ownerIsExpected && rules.Length == 2 && rules.All(rule =>
            !rule.IsInherited && rule.AccessControlType == AccessControlType.Allow) &&
            rules.Count(rule => currentUser.Equals(rule.IdentityReference)) == 1 &&
            rules.Count(rule => rule.IdentityReference.Value.StartsWith(
                "S-1-15-2-", StringComparison.Ordinal)) == 1;
    }

    private static bool IsSuffixGuid(string name, string prefix) =>
        name.Length == prefix.Length + 32 &&
        Guid.TryParseExact(name[prefix.Length..], "N", out _);

    private static bool IsRunOrNopeProfileName(string profile) =>
        profile.StartsWith("RunOrNope.Worker.", StringComparison.Ordinal) &&
        profile.Length <= 128 &&
        profile.All(character => char.IsAsciiLetterOrDigit(character) || character == '.');
}
