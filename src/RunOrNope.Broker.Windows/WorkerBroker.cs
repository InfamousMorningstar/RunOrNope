using System.Collections.Immutable;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using RunOrNope.Contracts;
using RunOrNope.Worker;

namespace RunOrNope.Broker.Windows;

public interface IWorkerBroker
{
    Task<ScanResult> AnalyzeAsync(
        SafeFileHandle sampleHandle, ScanRequest request, CancellationToken cancellationToken);
}

public sealed class WorkerBroker : IWorkerBroker
{
    private readonly string _workerExecutable;
    private readonly string? _packageSourceRoot;
    private readonly WorkerPackageManifest? _packageManifest;
    private readonly Action<string>? _prepareOutputForTesting;
    private readonly Action<string>? _attemptPackageReplacementDuringSealForTesting;
    private readonly WorkerIsolationPolicy _policy;

    public WorkerBroker() : this(
        string.Empty, packageManifest: null, WorkerIsolationPolicy.Default, trusted: true)
    {
    }

    private WorkerBroker(
        string packageSourceRoot, WorkerPackageManifest? packageManifest,
        WorkerIsolationPolicy policy, bool trusted, Action<string>? prepareOutputForTesting = null,
        Action<string>? attemptPackageReplacementDuringSealForTesting = null)
    {
        _ = trusted;
        _packageSourceRoot = packageSourceRoot;
        _packageManifest = packageManifest;
        _workerExecutable = packageManifest is null
            ? string.Empty
            : Path.Combine(packageSourceRoot, packageManifest.Document.EntryPoint);
        _policy = policy;
        _prepareOutputForTesting = prepareOutputForTesting;
        _attemptPackageReplacementDuringSealForTesting =
            attemptPackageReplacementDuringSealForTesting;
    }

    internal WorkerBroker(
        string packageSourceRoot, WorkerPackageManifest packageManifest,
        WorkerIsolationPolicy? policy = null, Action<string>? prepareOutputForTesting = null,
        Action<string>? attemptPackageReplacementDuringSealForTesting = null) : this(
            packageSourceRoot, packageManifest, policy ?? WorkerIsolationPolicy.Default,
            trusted: true, prepareOutputForTesting,
            attemptPackageReplacementDuringSealForTesting) { }

    public static IWorkerBroker CreateAuthenticated(
        string packageSourceRoot, byte[] manifestJson, byte[] signature, byte[] trustedPublicKey)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(packageSourceRoot);
        ArgumentNullException.ThrowIfNull(manifestJson);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(trustedPublicKey);
        return new WorkerBroker(packageSourceRoot,
            WorkerPackageManifest.Authenticate(manifestJson, signature, trustedPublicKey),
            WorkerIsolationPolicy.Default, trusted: true);
    }

    public async Task<ScanResult> AnalyzeAsync(
        SafeFileHandle sampleHandle, ScanRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sampleHandle);
        ArgumentNullException.ThrowIfNull(request);
        cancellationToken.ThrowIfCancellationRequested();
        if (sampleHandle.IsInvalid || sampleHandle.IsClosed)
            throw new ArgumentException("A live intake handle is required.", nameof(sampleHandle));

        try
        {
            _ = GetSampleSize(sampleHandle);
            return await AnalyzeIsolatedAsync(sampleHandle, request, null, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IsolationUnavailableException or IOException or UnauthorizedAccessException or
                WorkerProtocolException or ContractValidationException)
        {
            return MapIsolationFailure(exception);
        }
    }

    internal async Task<ScanResult> AnalyzeProbeAsync(
        SafeFileHandle sampleHandle, WorkerProbeRequest probe, CancellationToken cancellationToken)
    {
        try
        {
            return await AnalyzeIsolatedAsync(sampleHandle,
                new ScanRequest(string.Empty, ScanMode.Quick), probe, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is IsolationUnavailableException or IOException or UnauthorizedAccessException or
                WorkerProtocolException or ContractValidationException)
        {
            return MapIsolationFailure(exception);
        }
    }

    public static ScanResult MapIsolationFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return new(
            string.Empty,
            AnalysisStatus.IsolationUnavailable,
            ArtifactCompleteness.Unavailable,
            ImmutableArray<ArtifactNode>.Empty,
            ImmutableArray<Observation>.Empty,
            ImmutableArray<CapabilityFinding>.Empty,
            ImmutableArray.Create(
                $"Analysis did not run because the required isolation could not be established: {exception.Message}"));
    }

    private async Task<ScanResult> AnalyzeIsolatedAsync(
        SafeFileHandle sampleHandle, ScanRequest request, WorkerProbeRequest? probe,
        CancellationToken cancellationToken)
    {
        if (_packageManifest is null)
            throw new IsolationUnavailableException("An authenticated packaged worker manifest is required.");
        if (!Path.IsPathFullyQualified(_workerExecutable))
            throw new IsolationUnavailableException("The packaged worker root is invalid.");
        if (_policy.CapabilitySids.Count != 0)
            throw new IsolationUnavailableException("Worker network or other capabilities are forbidden.");

        // Independently hash the sample through the broker's own handle so the untrusted
        // worker's returned root identity can be verified before any of its result is
        // trusted. Positioned reads leave the shared file pointer untouched, so this does
        // not disturb the worker's own read of the duplicated handle. Skipped for probes,
        // which analyse a generated bundle rather than the submitted sample.
        string? expectedSha256 = null;
        var expectedSize = 0L;
        if (probe is null)
        {
            expectedSize = RandomAccess.GetLength(sampleHandle);
            expectedSha256 = ComputeSampleSha256(sampleHandle, cancellationToken);
        }

        using var profile = AppContainerProfile.Create();
        var outputDirectory = profile.CreatePrivateOutputDirectory();
        var packageDirectory = profile.CreatePrivatePackageDirectory();
        try
        {
            _prepareOutputForTesting?.Invoke(outputDirectory);
            using var packageLease = WorkerPackageStager.Stage(
                _packageSourceRoot!, packageDirectory, _packageManifest,
                new System.Security.Principal.SecurityIdentifier(profile.Sid),
                _attemptPackageReplacementDuringSealForTesting);
            var launchExecutable = packageLease.EntryPoint;
            using var job = JobObject.Create(_policy);
            using var outputHandle = OpenPrivateOutput(outputDirectory);
            using var requestPipe = new AnonymousPipeServerStream(
                PipeDirection.Out, HandleInheritability.Inheritable);
            using var responsePipe = new AnonymousPipeServerStream(
                PipeDirection.In, HandleInheritability.Inheritable);
            if (!NativeMethods.DuplicateHandle(NativeMethods.GetCurrentProcess(), sampleHandle,
                    NativeMethods.GetCurrentProcess(), out var childSample, 0, true,
                    NativeMethods.DuplicateSameAccess))
                throw new IsolationUnavailableException(
                    $"The intake handle could not be duplicated (error {Marshal.GetLastWin32Error()}).");
            using (childSample)
            using (var attributes = WorkerAttributeList.Create(
                       profile.Sid,
                       [childSample.DangerousGetHandle(), outputHandle.DangerousGetHandle(),
                        requestPipe.ClientSafePipeHandle.DangerousGetHandle(),
                        responsePipe.ClientSafePipeHandle.DangerousGetHandle()],
                       _policy))
            {
                var command = $"\"{launchExecutable}\" --broker " +
                              $"{childSample.DangerousGetHandle()} " +
                              $"{outputHandle.DangerousGetHandle()} " +
                              $"{requestPipe.ClientSafePipeHandle.DangerousGetHandle()} " +
                              $"{responsePipe.ClientSafePipeHandle.DangerousGetHandle()}";
                var startup = new NativeMethods.StartupInfoEx
                {
                    StartupInfo = { Cb = checked((uint)Marshal.SizeOf<NativeMethods.StartupInfoEx>()) },
                    AttributeList = attributes.Pointer
                };
                if (!NativeMethods.CreateProcessW(launchExecutable, command, IntPtr.Zero, IntPtr.Zero,
                        true, NativeMethods.CreateSuspended | NativeMethods.ExtendedStartupInfoPresent,
                        IntPtr.Zero, packageDirectory, ref startup, out var process))
                    throw new IsolationUnavailableException(
                        $"The AppContainer worker could not be created (error {Marshal.GetLastWin32Error()}).");

                try
                {
                    if (!NativeMethods.AssignProcessToJobObject(job.Handle, process.Process))
                        throw new IsolationUnavailableException(
                            $"The worker could not be assigned to its Job Object (error {Marshal.GetLastWin32Error()}).");
                    VerifySuspendedProcess(
                        process.Process, launchExecutable, profile.Sid, job, _policy);
                    if (NativeMethods.ResumeThread(process.Thread) == uint.MaxValue)
                        throw new IsolationUnavailableException(
                            $"The isolated worker could not be resumed (error {Marshal.GetLastWin32Error()}).");

                    requestPipe.DisposeLocalCopyOfClientHandle();
                    responsePipe.DisposeLocalCopyOfClientHandle();
                    var envelope = new WorkerRequestEnvelope(
                        WorkerProtocol.CurrentVersion,
                        request.Mode == ScanMode.Quick ? "quick" : "deep",
                        GetSampleSize(sampleHandle), probe);
                    await WorkerProtocol.WriteJsonFrameAsync(requestPipe, envelope, cancellationToken)
                        .ConfigureAwait(false);
                    var readTask = WorkerProtocol.ReadScanResultAsync(
                        responsePipe, cancellationToken).AsTask();
                    var response = await readTask.WaitAsync(_policy.WallClockTimeout, cancellationToken)
                        .ConfigureAwait(false);
                    if (expectedSha256 is not null)
                        WorkerResultIntegrity.EnsureRootIdentity(response, expectedSha256, expectedSize);
                    return response;
                }
                catch (TimeoutException exception)
                {
                    _ = NativeMethods.TerminateProcess(process.Process, 1460);
                    throw new IsolationUnavailableException("The isolated worker exceeded its wall-clock limit.", exception);
                }
                finally
                {
                    TerminateAndWait(process.Process);
                    NativeMethods.CloseHandle(process.Thread);
                    NativeMethods.CloseHandle(process.Process);
                }
            }
        }
        finally
        {
            try { Directory.Delete(outputDirectory, recursive: true); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            { /* Remains ACL-private for deliberate manual inspection and cleanup. */ }
            try
            {
                RestoreBrokerDeleteAccess(packageDirectory);
                Directory.Delete(packageDirectory, recursive: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            { /* Remains ACL-private and read-only to the disposed worker SID. */ }
        }
    }

    private static void RestoreBrokerDeleteAccess(string directory)
    {
        var brokerSid = WindowsIdentity.GetCurrent().User ??
            throw new IsolationUnavailableException("The broker SID is unavailable.");
        foreach (var path in Directory.EnumerateFiles(directory))
        {
            var security = new FileSecurity();
            security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new FileSystemAccessRule(
                brokerSid, FileSystemRights.FullControl, AccessControlType.Allow));
            new FileInfo(path).SetAccessControl(security);
        }
        var directorySecurity = new DirectorySecurity();
        directorySecurity.SetAccessRuleProtection(true, false);
        directorySecurity.AddAccessRule(new FileSystemAccessRule(
            brokerSid, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(directorySecurity);
    }

    private static void TerminateAndWait(IntPtr process)
    {
        _ = NativeMethods.TerminateProcess(process, 1);
        var wait = NativeMethods.WaitForSingleObject(process, 5_000);
        if (wait is not NativeMethods.WaitObject0)
        {
            // Closing the enclosing kill-on-close Job is the final bounded
            // lifecycle control. Cleanup retains locked private resources for
            // deliberate manual inspection rather than racing deletion.
        }
    }

    private static string ComputeSampleSha256(SafeFileHandle handle, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        var length = RandomAccess.GetLength(handle);
        var offset = 0L;
        while (offset < length)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var read = RandomAccess.Read(handle, buffer, offset);
            if (read == 0) break;
            hash.AppendData(buffer.AsSpan(0, read));
            offset += read;
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }

    private static long GetSampleSize(SafeFileHandle handle)
    {
        if (!NativeMethods.GetFileSizeEx(handle, out var size) || size < 0)
            throw new IsolationUnavailableException("The broker could not verify the intake handle size.");
        return size;
    }

    private static SafeFileHandle OpenPrivateOutput(string path)
    {
        var handle = NativeMethods.CreateFileW(path,
            NativeMethods.FileListDirectory | NativeMethods.FileAddFile | NativeMethods.FileReadAttributes,
            NativeMethods.FileShareRead | NativeMethods.FileShareWrite | NativeMethods.FileShareDelete,
            IntPtr.Zero, NativeMethods.OpenExisting,
            NativeMethods.FileFlagBackupSemantics | NativeMethods.FileFlagOpenReparsePoint, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new IsolationUnavailableException("The private output directory handle could not be opened.");
        }
        if (!NativeMethods.SetHandleInformation(
                handle, NativeMethods.HandleFlagInherit, NativeMethods.HandleFlagInherit))
        {
            handle.Dispose();
            throw new IsolationUnavailableException(
                "The private output directory handle could not be allowlisted for inheritance.");
        }
        return handle;
    }

    private static void VerifySuspendedProcess(
        IntPtr process, string expectedImagePath, IntPtr expectedPackageSid,
        JobObject job, WorkerIsolationPolicy policy)
    {
        var image = new char[32_768];
        var imageLength = (uint)image.Length;
        if (!NativeMethods.QueryFullProcessImageNameW(process, 0, image, ref imageLength) ||
            !StringComparer.OrdinalIgnoreCase.Equals(
                Path.GetFullPath(new string(image, 0, checked((int)imageLength))),
                Path.GetFullPath(expectedImagePath)))
            throw new IsolationUnavailableException(
                "The suspended worker image path does not match the authenticated staged entrypoint.");
        if (!NativeMethods.OpenProcessToken(process, NativeMethods.TokenQuery, out var token))
            throw new IsolationUnavailableException("The suspended worker token could not be opened.");
        using (token)
        {
            var isAppContainer = ReadTokenInt32(token, NativeMethods.TokenIsAppContainer);
            if (isAppContainer != 1)
                throw new IsolationUnavailableException("The suspended worker is not an AppContainer.");
            var packageInfo = ReadTokenBuffer(token, NativeMethods.TokenAppContainerSid);
            try
            {
                var actualSid = Marshal.ReadIntPtr(packageInfo);
                if (actualSid == IntPtr.Zero || !NativeMethods.EqualSid(actualSid, expectedPackageSid))
                    throw new IsolationUnavailableException("The worker package SID does not match its unique profile.");
            }
            finally { Marshal.FreeHGlobal(packageInfo); }

            var capabilities = ReadTokenBuffer(token, NativeMethods.TokenCapabilities);
            try
            {
                if (Marshal.ReadInt32(capabilities) != 0)
                    throw new IsolationUnavailableException("The worker token unexpectedly contains capabilities.");
            }
            finally { Marshal.FreeHGlobal(capabilities); }
        }

        if (!NativeMethods.IsProcessInJob(process, job.Handle, out var inExpectedJob) || !inExpectedJob)
            throw new IsolationUnavailableException("The worker is not in the expected Job Object.");
        var limits = job.QueryLimits();
        if (limits.ActiveProcessLimit != policy.ActiveProcessLimit ||
            limits.ProcessMemoryBytes != policy.ProcessMemoryBytes ||
            limits.ProcessCpuTime != policy.ProcessCpuTime ||
            limits.LimitFlags != JobObject.RequiredLimitFlags || !limits.KillOnClose)
            throw new IsolationUnavailableException("The worker Job limits changed after assignment.");

        if (!NativeMethods.GetProcessMitigationPolicy64(process, 0, out var dep, sizeof(ulong)) ||
            (dep & 1) == 0)
            throw new IsolationUnavailableException("The effective DEP mitigation was not verified.");
        RequireMitigation(process, 1, 0b111, "ASLR");
        RequireMitigation(process, 6, 1, "extension-point disable");
        RequireMitigation(process, 7, 1, "CFG");
        RequireMitigation(process, 10, 0b111, "image-load");
        RequireMitigation(process, 13, 1, "child-process restriction");
        if (policy.ProhibitDynamicCode) RequireMitigation(process, 2, 1, "dynamic-code prohibition");
    }

    private static int ReadTokenInt32(SafeFileHandle token, int informationClass)
    {
        var buffer = ReadTokenBuffer(token, informationClass);
        try { return Marshal.ReadInt32(buffer); }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static IntPtr ReadTokenBuffer(SafeFileHandle token, int informationClass)
    {
        uint required = 0;
        _ = NativeMethods.GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out required);
        if (required == 0)
            throw new IsolationUnavailableException("Windows did not size required token information.");
        var buffer = Marshal.AllocHGlobal(checked((int)required));
        if (!NativeMethods.GetTokenInformation(token, informationClass, buffer, required, out _))
        {
            Marshal.FreeHGlobal(buffer);
            throw new IsolationUnavailableException("Windows could not verify required token information.");
        }
        return buffer;
    }

    private static void RequireMitigation(IntPtr process, int policy, uint requiredFlags, string name)
    {
        if (!NativeMethods.GetProcessMitigationPolicy(process, policy, out var flags, sizeof(uint)) ||
            (flags & requiredFlags) != requiredFlags)
            throw new IsolationUnavailableException($"The effective {name} mitigation was not verified.");
    }
}

internal sealed class WorkerAttributeList : IDisposable
{
    private readonly List<IntPtr> _allocations = [];
    internal IntPtr Pointer { get; private set; }

    private WorkerAttributeList() { }

    internal static WorkerAttributeList Create(
        IntPtr appContainerSid, ReadOnlySpan<IntPtr> handles, WorkerIsolationPolicy policy)
    {
        if (appContainerSid == IntPtr.Zero || handles.Length != 4 ||
            handles.Contains(IntPtr.Zero) || handles.ToArray().Distinct().Count() != handles.Length)
            throw new IsolationUnavailableException("The explicit worker handle list is invalid.");
        var result = new WorkerAttributeList();
        try
        {
            nuint size = 0;
            _ = NativeMethods.InitializeProcThreadAttributeList(IntPtr.Zero, 4, 0, ref size);
            if (size == 0) throw new IsolationUnavailableException("Windows did not size the launch attribute list.");
            result.Pointer = Marshal.AllocHGlobal(checked((nint)size));
            if (!NativeMethods.InitializeProcThreadAttributeList(result.Pointer, 4, 0, ref size))
                throw new IsolationUnavailableException(
                    $"Windows could not initialize launch attributes (error {Marshal.GetLastWin32Error()}).");

            var handleBytes = checked(handles.Length * IntPtr.Size);
            var handleBuffer = result.Alloc(handleBytes);
            Marshal.Copy(handles.ToArray(), 0, handleBuffer, handles.Length);
            result.Update(NativeMethods.ProcThreadAttributeHandleList, handleBuffer, checked((nuint)handleBytes));

            var capabilities = new NativeMethods.SecurityCapabilities
            {
                AppContainerSid = appContainerSid,
                Capabilities = IntPtr.Zero,
                CapabilityCount = 0,
                Reserved = 0
            };
            var capabilityBuffer = result.Alloc(Marshal.SizeOf<NativeMethods.SecurityCapabilities>());
            Marshal.StructureToPtr(capabilities, capabilityBuffer, false);
            result.Update(NativeMethods.ProcThreadAttributeSecurityCapabilities, capabilityBuffer,
                checked((nuint)Marshal.SizeOf<NativeMethods.SecurityCapabilities>()));

            var mitigation = BuildMitigationMask(policy);
            var mitigationBuffer = result.Alloc(sizeof(ulong));
            Marshal.WriteInt64(mitigationBuffer, unchecked((long)mitigation));
            result.Update(NativeMethods.ProcThreadAttributeMitigationPolicy, mitigationBuffer, sizeof(ulong));

            if (!policy.DenyChildProcesses)
                throw new IsolationUnavailableException("Worker child-process denial is required.");
            var childPolicyBuffer = result.Alloc(sizeof(uint));
            Marshal.WriteInt32(childPolicyBuffer, checked((int)NativeMethods.ChildProcessRestricted));
            result.Update(NativeMethods.ProcThreadAttributeChildProcessPolicy, childPolicyBuffer, sizeof(uint));
            return result;
        }
        catch
        {
            result.Dispose();
            throw;
        }
    }

    internal static ulong BuildMitigationMask(WorkerIsolationPolicy policy)
    {
        var mitigation = NativeMethods.MitigationDep | NativeMethods.MitigationAslr |
                         NativeMethods.MitigationCfg;
        if (policy.DisableExtensionPoints)
            mitigation |= NativeMethods.MitigationExtensionPoints;
        if (policy.RestrictRemoteAndLowIntegrityImagesPreferSystem32)
            mitigation |= NativeMethods.MitigationImageLoad;
        if (policy.ProhibitDynamicCode)
            mitigation |= NativeMethods.MitigationDynamicCode;
        return mitigation;
    }

    private IntPtr Alloc(int bytes)
    {
        var value = Marshal.AllocHGlobal(bytes);
        _allocations.Add(value);
        return value;
    }

    private void Update(int attribute, IntPtr value, nuint size)
    {
        if (!NativeMethods.UpdateProcThreadAttribute(
                Pointer, 0, (IntPtr)attribute, value, size, IntPtr.Zero, IntPtr.Zero))
            throw new IsolationUnavailableException(
                $"Windows rejected a required launch attribute (error {Marshal.GetLastWin32Error()}).");
    }

    public void Dispose()
    {
        if (Pointer != IntPtr.Zero)
        {
            NativeMethods.DeleteProcThreadAttributeList(Pointer);
            Marshal.FreeHGlobal(Pointer);
            Pointer = IntPtr.Zero;
        }
        foreach (var allocation in _allocations) Marshal.FreeHGlobal(allocation);
        _allocations.Clear();
    }
}
