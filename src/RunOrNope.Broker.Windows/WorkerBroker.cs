using System.Collections.Immutable;
using System.IO.Pipes;
using System.Runtime.InteropServices;
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
    private readonly WorkerIsolationPolicy _policy;

    public WorkerBroker() : this(
        Path.Combine(AppContext.BaseDirectory, "RunOrNope.Worker.exe"),
        WorkerIsolationPolicy.Default)
    {
    }

    internal WorkerBroker(string workerExecutable, WorkerIsolationPolicy? policy = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(workerExecutable);
        _workerExecutable = workerExecutable;
        _policy = policy ?? WorkerIsolationPolicy.Default;
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
            return await AnalyzeIsolatedAsync(sampleHandle, request, cancellationToken).ConfigureAwait(false);
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
        SafeFileHandle sampleHandle, ScanRequest request, CancellationToken cancellationToken)
    {
        if (!Path.IsPathFullyQualified(_workerExecutable) || !File.Exists(_workerExecutable))
            throw new IsolationUnavailableException("The packaged worker executable is unavailable.");
        if (_policy.CapabilitySids.Count != 0)
            throw new IsolationUnavailableException("Worker network or other capabilities are forbidden.");

        using var profile = AppContainerProfile.Create();
        var outputDirectory = profile.CreatePrivateOutputDirectory();
        try
        {
            using var job = JobObject.Create(_policy);
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
                       [childSample.DangerousGetHandle(),
                        requestPipe.ClientSafePipeHandle.DangerousGetHandle(),
                        responsePipe.ClientSafePipeHandle.DangerousGetHandle()],
                       _policy))
            {
                var command = $"\"{_workerExecutable}\" --broker " +
                              $"{childSample.DangerousGetHandle()} " +
                              $"{requestPipe.ClientSafePipeHandle.DangerousGetHandle()} " +
                              $"{responsePipe.ClientSafePipeHandle.DangerousGetHandle()}";
                var startup = new NativeMethods.StartupInfoEx
                {
                    StartupInfo = { Cb = checked((uint)Marshal.SizeOf<NativeMethods.StartupInfoEx>()) },
                    AttributeList = attributes.Pointer
                };
                if (!NativeMethods.CreateProcessW(_workerExecutable, command, IntPtr.Zero, IntPtr.Zero,
                        true, NativeMethods.CreateSuspended | NativeMethods.ExtendedStartupInfoPresent,
                        IntPtr.Zero, Path.GetDirectoryName(_workerExecutable), ref startup, out var process))
                    throw new IsolationUnavailableException(
                        $"The AppContainer worker could not be created (error {Marshal.GetLastWin32Error()}).");

                try
                {
                    if (!NativeMethods.AssignProcessToJobObject(job.Handle, process.Process))
                        throw new IsolationUnavailableException(
                            $"The worker could not be assigned to its Job Object (error {Marshal.GetLastWin32Error()}).");
                    if (NativeMethods.ResumeThread(process.Thread) == uint.MaxValue)
                        throw new IsolationUnavailableException(
                            $"The isolated worker could not be resumed (error {Marshal.GetLastWin32Error()}).");

                    requestPipe.DisposeLocalCopyOfClientHandle();
                    responsePipe.DisposeLocalCopyOfClientHandle();
                    var envelope = new WorkerRequestEnvelope(
                        WorkerProtocol.CurrentVersion,
                        request.Mode == ScanMode.Quick ? "quick" : "deep",
                        GetSampleSize(sampleHandle));
                    await WorkerProtocol.WriteJsonFrameAsync(requestPipe, envelope, cancellationToken)
                        .ConfigureAwait(false);
                    var readTask = WorkerProtocol.ReadJsonFrameAsync<WorkerResponseEnvelope>(
                        responsePipe, cancellationToken).AsTask();
                    var response = await readTask.WaitAsync(_policy.WallClockTimeout, cancellationToken)
                        .ConfigureAwait(false);
                    if (response.Version != WorkerProtocol.CurrentVersion)
                        throw new IsolationUnavailableException("The worker returned an unsupported protocol version.");
                    return ScanContractJson.Deserialize(response.ResultJson);
                }
                catch (TimeoutException exception)
                {
                    _ = NativeMethods.TerminateProcess(process.Process, 1460);
                    throw new IsolationUnavailableException("The isolated worker exceeded its wall-clock limit.", exception);
                }
                finally
                {
                    _ = NativeMethods.TerminateProcess(process.Process, 1);
                    NativeMethods.CloseHandle(process.Thread);
                    NativeMethods.CloseHandle(process.Process);
                }
            }
        }
        finally
        {
            try { Directory.Delete(outputDirectory, recursive: true); }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            { /* Remains ACL-private; a later broker startup cleanup may retry. */ }
        }
    }

    private static long GetSampleSize(SafeFileHandle handle)
    {
        if (!NativeMethods.GetFileSizeEx(handle, out var size) || size < 0)
            throw new IsolationUnavailableException("The broker could not verify the intake handle size.");
        return size;
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
        if (appContainerSid == IntPtr.Zero || handles.Length != 3 ||
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

            var mitigation = NativeMethods.MitigationDep | NativeMethods.MitigationAslr |
                             NativeMethods.MitigationCfg | NativeMethods.MitigationExtensionPoints |
                             NativeMethods.MitigationImageLoad;
            if (policy.ProhibitDynamicCode) mitigation |= NativeMethods.MitigationDynamicCode;
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
