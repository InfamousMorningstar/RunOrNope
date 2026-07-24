using Microsoft.Win32.SafeHandles;

namespace RunOrNope.Broker.Windows;

/// <summary>
/// Owns the worker Job Object. This type intentionally remains unavailable
/// until assignment and every configured limit can be verified atomically.
/// It is a resource/lifecycle control, not the network security boundary.
/// </summary>
internal sealed class JobObject : IDisposable
{
    private SafeFileHandle? _handle;

    private JobObject(SafeFileHandle handle) => _handle = handle;
    internal SafeFileHandle Handle => _handle ?? throw new ObjectDisposedException(nameof(JobObject));

    internal static JobObject Create(WorkerIsolationPolicy policy)
    {
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.ActiveProcessLimit != 1 || !policy.KillOnJobClose ||
            policy.ProcessMemoryBytes <= 0 || policy.ProcessCpuTime <= TimeSpan.Zero)
            throw new IsolationUnavailableException("The worker Job policy is not safely bounded.");

        var handle = NativeMethods.CreateJobObjectW(IntPtr.Zero, null);
        if (handle.IsInvalid)
        {
            handle.Dispose();
            throw new IsolationUnavailableException(
                $"Windows could not create a Job Object (error {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}).");
        }

        try
        {
            var information = new NativeMethods.JobObjectExtendedLimitInformation
            {
                BasicLimitInformation =
                {
                    ActiveProcessLimit = policy.ActiveProcessLimit,
                    PerProcessUserTimeLimit = policy.ProcessCpuTime.Ticks,
                    LimitFlags = NativeMethods.JobObjectLimitActiveProcess |
                                 NativeMethods.JobObjectLimitKillOnJobClose |
                                 NativeMethods.JobObjectLimitProcessMemory |
                                 NativeMethods.JobObjectLimitProcessTime
                },
                ProcessMemoryLimit = checked((nuint)policy.ProcessMemoryBytes)
            };
            var size = checked((uint)System.Runtime.InteropServices.Marshal.SizeOf<
                NativeMethods.JobObjectExtendedLimitInformation>());
            if (!NativeMethods.SetInformationJobObject(
                    handle, NativeMethods.JobObjectExtendedLimitInformationClass, ref information, size))
                throw new IsolationUnavailableException(
                    $"Windows could not apply Job Object limits (error {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}).");

            var job = new JobObject(handle);
            var actual = job.QueryLimits();
            if (actual.ActiveProcessLimit != policy.ActiveProcessLimit ||
                actual.ProcessMemoryBytes != policy.ProcessMemoryBytes ||
                !actual.KillOnClose)
                throw new IsolationUnavailableException("Windows did not preserve the required Job Object limits.");
            return job;
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    internal JobLimits QueryLimits()
    {
        var handle = _handle ?? throw new ObjectDisposedException(nameof(JobObject));
        var size = checked((uint)System.Runtime.InteropServices.Marshal.SizeOf<
            NativeMethods.JobObjectExtendedLimitInformation>());
        if (!NativeMethods.QueryInformationJobObject(
                handle, NativeMethods.JobObjectExtendedLimitInformationClass, out var information, size, IntPtr.Zero))
            throw new IsolationUnavailableException(
                $"Windows could not verify Job Object limits (error {System.Runtime.InteropServices.Marshal.GetLastWin32Error()}).");
        return new(information.BasicLimitInformation.ActiveProcessLimit,
            checked((long)information.ProcessMemoryLimit),
            (information.BasicLimitInformation.LimitFlags &
             NativeMethods.JobObjectLimitKillOnJobClose) != 0);
    }

    public void Dispose() => Interlocked.Exchange(ref _handle, null)?.Dispose();
}

internal readonly record struct JobLimits(uint ActiveProcessLimit, long ProcessMemoryBytes, bool KillOnClose);
