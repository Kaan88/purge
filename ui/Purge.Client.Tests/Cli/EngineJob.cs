using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Purge.Client.Cli;

/// <summary>
/// A Windows job object with <c>JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE</c>, held for the client's lifetime: every engine
/// process is put in it right after it starts, so when the app ends (even when it crashes) Windows ends the engine
/// and everything the engine started that did not leave the job.
/// </summary>
internal sealed partial class EngineJob : IDisposable
{
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x2000;

    private nint _handle;

    private EngineJob(nint handle) => _handle = handle;

    /// <summary>The job, or null when Windows refused it (the client then relies on killing what it tracks).</summary>
    public static EngineJob? TryCreate()
    {
        if (!OperatingSystem.IsWindows()) return null;
        var handle = CreateJobObjectW(0, 0);
        if (handle == 0) return null;
        var info = new ExtendedLimitInformation { LimitFlags = JobObjectLimitKillOnJobClose };
        if (!SetInformationJobObject(handle, JobObjectExtendedLimitInformation, ref info, (uint)Marshal.SizeOf<ExtendedLimitInformation>()))
        {
            CloseHandle(handle);
            return null;
        }
        return new EngineJob(handle);
    }

    /// <summary>Puts <paramref name="process"/> in the job; false when Windows refused.</summary>
    public bool Assign(Process process)
    {
        var handle = _handle;
        if (handle == 0) return false;
        try { return AssignProcessToJobObject(handle, process.Handle); }
        catch (InvalidOperationException) { return false; }
    }

    /// <summary>Closes the job, which ends every process still in it.</summary>
    public void Dispose()
    {
        var handle = Interlocked.Exchange(ref _handle, 0);
        if (handle != 0) CloseHandle(handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimitInformation
    {
        // JOBOBJECT_BASIC_LIMIT_INFORMATION
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
        // IO_COUNTERS
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
        // The rest of JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint CreateJobObjectW(nint attributes, nint name);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetInformationJobObject(nint job, int infoClass, ref ExtendedLimitInformation info, uint length);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AssignProcessToJobObject(nint job, nint process);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}
