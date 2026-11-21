using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Purge.Client.Stdio;

/// <summary>
/// <c>purge-engine --stdio</c> as a child process: created suspended, put in a kill-on-close job, then resumed, with
/// two inherited pipes (the engine's stdin and stdout) and nothing else inherited. The engine's stderr goes to NUL;
/// the protocol never uses it. Closing the job ends the engine and whatever it started, even when the UI crashes.
/// </summary>
internal sealed unsafe partial class EngineProcess : IDisposable
{
    private const uint CreateSuspended = 0x4;
    private const uint ExtendedStartupInfoPresent = 0x80000;
    private const uint CreateNoWindow = 0x08000000;
    private const uint StartfUseStdHandles = 0x100;
    private const nuint ProcThreadAttributeHandleList = 0x20002;
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JobObjectLimitKillOnJobClose = 0x2000;
    private const uint StillActive = 259;

    private nint _job;
    private nint _process;
    private readonly object _gate = new();

    private EngineProcess() { }

    /// <summary>The engine's stdin (we write requests here).</summary>
    public Stream Input { get; private set; } = Stream.Null;

    /// <summary>The engine's stdout (we read responses and notifications here).</summary>
    public Stream Output { get; private set; } = Stream.Null;

    /// <summary>Starts <paramref name="exePath"/> with <paramref name="arguments"/>; throws when it cannot.</summary>
    public static EngineProcess Start(string exePath, string arguments)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("The engine link needs Windows.");
        if (!File.Exists(exePath)) throw new FileNotFoundException($"The engine was not found at {exePath}.", exePath);

        var self = new EngineProcess();
        nint inRead = 0, inWrite = 0, outRead = 0, outWrite = 0, nul = 0, attributes = 0;
        var thread = (nint)0;
        try
        {
            self._job = CreateJob();
            var sa = new SecurityAttributes { Length = (uint)sizeof(SecurityAttributes), InheritHandle = 1 };
            if (!CreatePipe(out inRead, out inWrite, ref sa, 0) || !CreatePipe(out outRead, out outWrite, ref sa, 0))
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            // Our ends must not be inherited by the engine.
            if (!SetHandleInformation(inWrite, 1, 0) || !SetHandleInformation(outRead, 1, 0))
                throw new Win32Exception(Marshal.GetLastPInvokeError());
            nul = CreateFileW("NUL", 0x40000000, 3, ref sa, 3, 0, 0);
            if (nul == -1) { nul = 0; throw new Win32Exception(Marshal.GetLastPInvokeError()); }

            // Only the three handles named here are inherited.
            var inherit = stackalloc nint[3] { inRead, outWrite, nul };
            nuint size = 0;
            InitializeProcThreadAttributeList(0, 1, 0, ref size);
            attributes = (nint)NativeMemory.Alloc(size);
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size)
                || !UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributeHandleList, inherit, (nuint)(3 * sizeof(nint)), 0, 0))
                throw new Win32Exception(Marshal.GetLastPInvokeError());

            var info = new StartupInfoEx
            {
                StartupInfo = new StartupInfo
                {
                    Size = (uint)sizeof(StartupInfoEx), Flags = StartfUseStdHandles,
                    StdInput = inRead, StdOutput = outWrite, StdError = nul,
                },
                AttributeList = attributes,
            };
            // CreateProcessW may write into the command line, so it gets its own buffer.
            var command = $"\"{exePath}\" {arguments}\0".ToCharArray();
            fixed (char* commandLine = command)
            {
                if (!CreateProcessW(exePath, commandLine, 0, 0, true, CreateSuspended | ExtendedStartupInfoPresent | CreateNoWindow,
                        0, Path.GetDirectoryName(exePath), ref info, out var pi))
                    throw new Win32Exception(Marshal.GetLastPInvokeError());
                self._process = pi.Process;
                thread = pi.Thread;
            }
            if (!AssignProcessToJobObject(self._job, self._process))
            {
                var error = Marshal.GetLastPInvokeError();
                TerminateProcess(self._process, 1);
                throw new Win32Exception(error, "The engine could not be put in its job.");
            }
            if (ResumeThread(thread) == uint.MaxValue) throw new Win32Exception(Marshal.GetLastPInvokeError());

            self.Input = new FileStream(new SafeFileHandle(inWrite, true), FileAccess.Write, 1, false);
            inWrite = 0;
            self.Output = new FileStream(new SafeFileHandle(outRead, true), FileAccess.Read, 1, false);
            outRead = 0;
            return self;
        }
        catch
        {
            self.Dispose();
            throw;
        }
        finally
        {
            // The child's ends belong to the child now.
            foreach (var h in new[] { inRead, outWrite, nul, thread, inWrite, outRead })
                if (h != 0) CloseHandle(h);
            if (attributes != 0)
            {
                DeleteProcThreadAttributeList(attributes);
                NativeMemory.Free((void*)attributes);
            }
        }
    }

    /// <summary>The exit code once the engine has ended (waits up to <paramref name="waitMs"/>); null while it runs.</summary>
    public int? ExitCode(int waitMs)
    {
        lock (_gate)
        {
            if (_process == 0) return null;
            if (waitMs > 0) WaitForSingleObject(_process, (uint)waitMs);
            return GetExitCodeProcess(_process, out var code) && code != StillActive ? (int)code : null;
        }
    }

    /// <summary>Closes the pipes and the job, which ends the engine.</summary>
    public void Dispose()
    {
        try { Input.Dispose(); } catch (IOException) { }
        var job = Interlocked.Exchange(ref _job, 0);
        if (job != 0) CloseHandle(job);
        lock (_gate)
        {
            if (_process != 0) { CloseHandle(_process); _process = 0; }
        }
        // Output is left to its reader: closing the engine ends the stream, which ends the read.
    }

    private static nint CreateJob()
    {
        var job = CreateJobObjectW(0, 0);
        if (job == 0) throw new Win32Exception(Marshal.GetLastPInvokeError());
        var info = new ExtendedLimitInformation { LimitFlags = JobObjectLimitKillOnJobClose };
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref info, (uint)sizeof(ExtendedLimitInformation)))
        {
            var error = Marshal.GetLastPInvokeError();
            CloseHandle(job);
            throw new Win32Exception(error);
        }
        return job;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public uint Length;
        public nint SecurityDescriptor;
        public int InheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public uint Size;
        public nint Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public ushort ShowWindow, ReservedBytes;
        public nint Reserved2, StdInput, StdOutput, StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfoEx
    {
        public StartupInfo StartupInfo;
        public nint AttributeList;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public nint Process, Thread;
        public uint ProcessId, ThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public nuint MinimumWorkingSetSize;
        public nuint MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public nuint Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
        public nuint ProcessMemoryLimit;
        public nuint JobMemoryLimit;
        public nuint PeakProcessMemoryUsed;
        public nuint PeakJobMemoryUsed;
    }

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreateProcessW(string applicationName, char* commandLine, nint processAttributes, nint threadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint creationFlags, nint environment, string? currentDirectory,
        ref StartupInfoEx startupInfo, out ProcessInformation processInformation);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CreatePipe(out nint read, out nint write, ref SecurityAttributes attributes, uint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetHandleInformation(nint handle, uint mask, uint flags);

    [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    private static partial nint CreateFileW(string name, uint access, uint share, ref SecurityAttributes attributes, uint disposition,
        uint flags, nint template);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool InitializeProcThreadAttributeList(nint list, int count, int flags, ref nuint size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool UpdateProcThreadAttribute(nint list, uint flags, nuint attribute, nint* value, nuint size, nint previous,
        nint returnSize);

    [LibraryImport("kernel32.dll")]
    private static partial void DeleteProcThreadAttributeList(nint list);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint ResumeThread(nint thread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(nint process, uint exitCode);

    [LibraryImport("kernel32.dll")]
    private static partial uint WaitForSingleObject(nint handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(nint process, out uint exitCode);

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
