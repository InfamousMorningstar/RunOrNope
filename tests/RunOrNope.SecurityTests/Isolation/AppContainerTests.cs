using RunOrNope.Broker.Windows;
using System.Security.AccessControl;
using System.Security.Principal;
using Xunit;

namespace RunOrNope.SecurityTests.Isolation;

public sealed class AppContainerTests
{
    [Fact]
    public void Policy_has_no_capabilities_and_requires_every_security_control()
    {
        var policy = WorkerIsolationPolicy.Default;

        Assert.Empty(policy.CapabilitySids);
        Assert.Equal(1u, policy.ActiveProcessLimit);
        Assert.True(policy.DenyChildProcesses);
        Assert.True(policy.KillOnJobClose);
        // The current managed worker needs the CLR JIT. Native-AOT adapters
        // can opt into dynamic-code prohibition with a stricter policy.
        Assert.False(policy.ProhibitDynamicCode);
        Assert.True(policy.DisableExtensionPoints);
        Assert.True(policy.RestrictRemoteAndLowIntegrityImagesPreferSystem32);
        Assert.True(policy.RequirePrivateOutputAcl);
        Assert.InRange(policy.ProcessMemoryBytes, 16L * 1024 * 1024, 512L * 1024 * 1024);
        Assert.InRange(policy.WallClockTimeout, TimeSpan.FromMilliseconds(100), TimeSpan.FromMinutes(5));
    }

    [Fact]
    public void Mitigation_mask_is_derived_from_policy()
    {
        var strict = WorkerIsolationPolicy.Default;
        var managed = WorkerAttributeList.BuildMitigationMask(strict);
        Assert.NotEqual(0UL, managed & NativeMethods.MitigationExtensionPoints);
        Assert.NotEqual(0UL, managed & NativeMethods.MitigationImageLoad);
        Assert.Equal(0UL, managed & NativeMethods.MitigationDynamicCode);

        var native = strict with { ProhibitDynamicCode = true };
        Assert.NotEqual(0UL,
            WorkerAttributeList.BuildMitigationMask(native) & NativeMethods.MitigationDynamicCode);
    }

    [Fact]
    public void Broker_fails_closed_when_isolation_cannot_be_established()
    {
        var result = WorkerBroker.MapIsolationFailure(new InvalidOperationException("blocked"));

        Assert.Equal(RunOrNope.Contracts.AnalysisStatus.IsolationUnavailable, result.AnalysisStatus);
        Assert.Equal(RunOrNope.Contracts.ArtifactCompleteness.Unavailable, result.Completeness);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Unique_profile_names_are_not_reused()
    {
        Assert.NotEqual(AppContainerProfile.CreateUniqueName(), AppContainerProfile.CreateUniqueName());
    }

    [Fact]
    public void Disposable_profile_is_real_and_capability_free()
    {
        using var profile = AppContainerProfile.Create();

        Assert.NotEqual(IntPtr.Zero, profile.Sid);
        Assert.Empty(profile.Capabilities);
    }

    [Fact]
    public void Job_object_applies_and_verifies_required_limits()
    {
        using var job = JobObject.Create(WorkerIsolationPolicy.Default);
        var limits = job.QueryLimits();

        Assert.Equal(1u, limits.ActiveProcessLimit);
        Assert.Equal(WorkerIsolationPolicy.Default.ProcessMemoryBytes, limits.ProcessMemoryBytes);
        Assert.Equal(WorkerIsolationPolicy.Default.ProcessCpuTime, limits.ProcessCpuTime);
        Assert.True(limits.KillOnClose);
        Assert.Equal(JobObject.RequiredLimitFlags, limits.LimitFlags);
    }

    [Fact]
    public void Private_output_directory_grants_only_broker_and_worker_sid()
    {
        using var profile = AppContainerProfile.Create();
        using var unrelated = AppContainerProfile.Create();
        var path = profile.CreatePrivateOutputDirectory();
        try
        {
            var security = new DirectoryInfo(path).GetAccessControl();
            Assert.True(security.AreAccessRulesProtected);
            var identities = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .Select(rule => rule.IdentityReference.Value)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            Assert.Contains(WindowsIdentity.GetCurrent().User!.Value, identities);
            Assert.Contains(profile.SidString, identities);
            Assert.DoesNotContain(unrelated.SidString, identities);
            Assert.DoesNotContain(new SecurityIdentifier(WellKnownSidType.WorldSid, null).Value, identities);
        }
        finally
        {
            Directory.Delete(path, recursive: true);
        }
    }

    [Fact]
    public void Private_package_directory_is_read_execute_only_for_worker()
    {
        using var profile = AppContainerProfile.Create();
        var path = profile.CreatePrivatePackageDirectory();
        try
        {
            var rules = new DirectoryInfo(path).GetAccessControl()
                .GetAccessRules(true, false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>();
            var worker = Assert.Single(rules, rule =>
                rule.IdentityReference.Value.Equals(profile.SidString, StringComparison.OrdinalIgnoreCase));
            Assert.Equal(FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
                worker.FileSystemRights);
            Assert.Equal(AccessControlType.Allow, worker.AccessControlType);
            Assert.False(worker.IsInherited);
        }
        finally { Directory.Delete(path, true); }
    }

    [Fact]
    public void Automatic_scavenging_never_deletes_forgeable_filesystem_resources_or_live_profiles()
    {
        using var profile = AppContainerProfile.Create();
        var staleOutput = profile.CreatePrivateOutputDirectory();
        var stalePackage = profile.CreatePrivatePackageDirectory();
        var freshOutput = profile.CreatePrivateOutputDirectory();
        var now = DateTime.UtcNow;
        Directory.SetLastWriteTimeUtc(staleOutput, now - TimeSpan.FromDays(2));
        Directory.SetLastWriteTimeUtc(stalePackage, now - TimeSpan.FromDays(2));

        // There is deliberately no automatic cleanup API: forgeable
        // filesystem state cannot authorize recursive or profile deletion.
        Assert.True(Directory.Exists(staleOutput));
        Assert.True(Directory.Exists(stalePackage));
        Assert.True(Directory.Exists(freshOutput));
        Directory.Delete(staleOutput, true);
        Directory.Delete(stalePackage, true);
        Directory.Delete(freshOutput, true);
    }
}
