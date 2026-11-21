using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace Purge.Client.Broker;

/// <summary>How the launch of the administrator part ended.</summary>
public enum BrokerLaunchStatus
{
    /// <summary>The broker is running and answered the server check; <see cref="BrokerLaunchResult.Session"/> is set.</summary>
    Started,

    /// <summary>The user said No at the Windows prompt (error 1223). Show the cancelled bar; nothing changed.</summary>
    Cancelled,

    /// <summary>The account cannot elevate (a standard user): show "Purge needs an administrator account".</summary>
    NotAdministrator,

    /// <summary>The broker could not be started, or exited before its pipe existed (<see cref="BrokerLaunchResult.ExitCode"/>).</summary>
    CannotStart,

    /// <summary>The pipe was served by something other than the broker that was launched.</summary>
    ServerCheckFailed,

    /// <summary>The broker did not create its pipe within <see cref="BrokerLauncher.ConnectTimeout"/>.</summary>
    TimedOut,
}

/// <summary>The answer of <see cref="BrokerLauncher.LaunchAsync"/>.</summary>
public sealed class BrokerLaunchResult
{
    private BrokerLaunchResult(BrokerLaunchStatus status, BrokerSession? session, int? exitCode, int win32Error, string message)
    {
        Status = status;
        Session = session;
        ExitCode = exitCode;
        Win32Error = win32Error;
        Message = message;
    }

    public BrokerLaunchStatus Status { get; }

    /// <summary>The live broker connection; only set when <see cref="Status"/> is <see cref="BrokerLaunchStatus.Started"/>.</summary>
    public BrokerSession? Session { get; }

    /// <summary>The broker's exit code when it ended before the pipe existed.</summary>
    public int? ExitCode { get; }

    /// <summary>The Windows error behind a failure, or 0.</summary>
    public int Win32Error { get; }

    /// <summary>One sentence for the UI; for <see cref="BrokerLaunchStatus.Cancelled"/> it feeds the cancelled bar.</summary>
    public string Message { get; }

    public bool Ok => Status == BrokerLaunchStatus.Started;

    internal static BrokerLaunchResult Started(BrokerSession session) =>
        new(BrokerLaunchStatus.Started, session, null, 0, "");

    internal static BrokerLaunchResult Failed(BrokerLaunchStatus status, string message, int win32Error = 0, int? exitCode = null) =>
        new(status, null, exitCode, win32Error, message);
}

/// <summary>
/// The connected broker: its pipe client and the process handle <c>ShellExecuteExW</c> returned. The handle is held
/// so the pid cannot be reused while the UI talks to it, and the broker ends when this is disposed (the pipe closes;
/// the broker also holds the UI as its parent).
/// </summary>
public sealed partial class BrokerSession : IAsyncDisposable
{
    private readonly SafeProcessHandle _process;

    internal BrokerSession(BrokerRpcClient rpc, SafeProcessHandle process, int processId, string brokerPath)
    {
        Rpc = rpc;
        _process = process;
        ProcessId = processId;
        BrokerPath = brokerPath;
    }

    /// <summary>The JSON-RPC link to the broker (server check already passed).</summary>
    public BrokerRpcClient Rpc { get; }

    /// <summary>The broker's pid.</summary>
    public int ProcessId { get; }

    /// <summary>The broker executable that was launched.</summary>
    public string BrokerPath { get; }

    /// <summary>
    /// Lets the broker bring its own consent dialog to the foreground (design 3.3: called before <c>plan.execute</c>
    /// and the other consent requests). A refusal is not an error; the UI then names the prompt in its waiting state.
    /// </summary>
    public void AllowForeground() => _ = AllowSetForegroundWindow((uint)ProcessId);

    public async ValueTask DisposeAsync()
    {
        await Rpc.DisposeAsync().ConfigureAwait(false);
        _process.Dispose();
    }

    [LibraryImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool AllowSetForegroundWindow(uint processId);
}

/// <summary>
/// The launcher of design 3.3 step 1 and the client half of steps 3 and 4: the UI's own account pre-check, the
/// 128-bit pipe name, <c>ShellExecuteExW("runas")</c> on an STA thread with <c>SEE_MASK_NOCLOSEPROCESS</c>, a connect
/// with <c>SECURITY_IDENTIFICATION</c>, and <see cref="BrokerServerCheck"/> before a byte is sent. Nothing here runs at
/// app start; the first Uninstall, Restore or History-detail click calls it.
/// </summary>
public static partial class BrokerLauncher
{
    /// <summary>How long the broker may take to create its pipe (design 3.3 step 3: retry for up to 10 s).</summary>
    public static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    private const uint SeeMaskNoCloseProcess = 0x00000040;
    private const uint SeeMaskNoAsync = 0x00000100;
    private const int SwHide = 0;
    private const int ErrorCancelled = 1223;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPipeBusy = 231;
    private const int ErrorSemTimeout = 121;
    private const uint WaitObject0 = 0;
    private const uint StillActive = 259;
    private const uint TokenQuery = 0x8;
    private const int TokenElevation = 20;
    private const int TokenElevationType = 18;
    private const uint TokenElevationTypeLimited = 3;

    /// <summary><c>purge-broker.exe</c> beside this program (the release layout install.ps1 deploys).</summary>
    public static string PathBesideApp() => Path.Combine(AppContext.BaseDirectory, "purge-broker.exe");

    /// <summary>
    /// Starts <c>purge-broker.exe</c> elevated, waits for its pipe, and verifies the server before returning it.
    /// A cancelled Windows prompt is <see cref="BrokerLaunchStatus.Cancelled"/>; nothing is shown or started at app
    /// start. <paramref name="ownerWindow"/> is passed as the prompt's owner.
    /// </summary>
    public static async Task<BrokerLaunchResult> LaunchAsync(string brokerPath, nint ownerWindow = default,
        CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            return BrokerLaunchResult.Failed(BrokerLaunchStatus.CannotStart, "The administrator part is a Windows program.");

        if (Elevation() == ElevationKind.StandardUser)
            return BrokerLaunchResult.Failed(BrokerLaunchStatus.NotAdministrator,
                "Purge needs an administrator account to remove programs for all users.");

        if (string.IsNullOrWhiteSpace(brokerPath) || !File.Exists(brokerPath))
            return BrokerLaunchResult.Failed(BrokerLaunchStatus.CannotStart,
                $"The administrator part is missing: {brokerPath}.");
        brokerPath = Path.GetFullPath(brokerPath);

        ct.ThrowIfCancellationRequested();
        var (pid, creationTime) = CurrentProcessIdentity();
        var pipeName = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(16));
        var arguments = string.Create(CultureInfo.InvariantCulture,
            $"--pipe {pipeName} --parent {pid} --parent-ctime {creationTime}");
        var directory = Path.GetDirectoryName(brokerPath) ?? AppContext.BaseDirectory;

        var shell = await RunOnStaThreadAsync(() => RunShell(brokerPath, arguments, directory, ownerWindow)).ConfigureAwait(false);
        if (!shell.Ok) return ClassifyShellFailure(shell.Error);
        if (shell.Process == 0)
            return BrokerLaunchResult.Failed(BrokerLaunchStatus.CannotStart,
                "Windows started the administrator part but returned no process handle.");

        var process = new SafeProcessHandle(shell.Process, ownsHandle: true);
        var started = false;
        try
        {
            var result = await ConnectAsync(process, pipeName, brokerPath, ct).ConfigureAwait(false);
            if (!result.Ok) return result;
            started = true;
            return result;
        }
        finally
        {
            if (!started) process.Dispose();
        }
    }

    /// <summary>
    /// Maps a <c>ShellExecuteExW</c> failure. Error 1223 is the user saying No at the Windows prompt; the UI shows the
    /// cancelled bar (<c>ElevationPrompts.CancelledBar</c>) and starts nothing.
    /// </summary>
    public static BrokerLaunchResult ClassifyShellFailure(int error)
    {
        if (error == ErrorCancelled)
            return BrokerLaunchResult.Failed(BrokerLaunchStatus.Cancelled,
                "You cancelled the admin prompt. Nothing was changed.");
        return BrokerLaunchResult.Failed(BrokerLaunchStatus.CannotStart,
            "The administrator part could not start. " + new Win32Exception(error).Message, error);
    }

    private static async Task<BrokerLaunchResult> ConnectAsync(SafeProcessHandle process, string pipeName,
        string brokerPath, CancellationToken ct)
    {
        var pid = GetProcessId(process.DangerousGetHandle());
        var path = @"\\.\pipe\purge-" + pipeName;
        var deadline = Environment.TickCount64 + (long)ConnectTimeout.TotalMilliseconds;
        try
        {
            while (true)
            {
                var open = BrokerPipe.TryOpen(path, (int)pid, brokerPath);
                if (open.Check is { } failed)
                {
                    Terminate(process);
                    return BrokerLaunchResult.Failed(BrokerLaunchStatus.ServerCheckFailed, failed.Reason);
                }
                if (open.Stream is not null)
                {
                    var rpc = BrokerRpcClient.Over(open.TakeStream(), ownsStream: true);
                    return BrokerLaunchResult.Started(new BrokerSession(rpc, process, (int)pid, brokerPath));
                }
                var error = open.Win32Error;
                if (error != ErrorPipeBusy && error != ErrorFileNotFound && error != ErrorSemTimeout)
                    return BrokerLaunchResult.Failed(BrokerLaunchStatus.CannotStart,
                        "Purge could not connect to the administrator part. " + new Win32Exception(error).Message, error);

                if (TryExitCode(process, out var exitCode))
                    return BrokerLaunchResult.Failed(BrokerLaunchStatus.CannotStart,
                        $"The administrator part could not start (exit code {exitCode.ToString(CultureInfo.InvariantCulture)}).",
                        exitCode: exitCode);

                if (Environment.TickCount64 >= deadline)
                {
                    Terminate(process);
                    return BrokerLaunchResult.Failed(BrokerLaunchStatus.TimedOut,
                        $"The administrator part did not start within {ConnectTimeout.TotalSeconds:0} seconds.");
                }
                await Task.Delay(50, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
            Terminate(process);
            throw;
        }
    }

    private static bool TryExitCode(SafeProcessHandle process, out int exitCode)
    {
        exitCode = 0;
        if (WaitForSingleObject(process.DangerousGetHandle(), 0) != WaitObject0) return false;
        return GetExitCodeProcess(process.DangerousGetHandle(), out exitCode) && (uint)exitCode != StillActive;
    }

    private static void Terminate(SafeProcessHandle process)
    {
        if (!TryExitCode(process, out _)) _ = TerminateProcess(process.DangerousGetHandle(), 1);
    }

    private static (int Pid, ulong CreationTime) CurrentProcessIdentity()
    {
        if (!GetProcessTimes(GetCurrentProcess(), out var created, out _, out _, out _))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        var time = ((ulong)created.High << 32) | created.Low;
        return (Environment.ProcessId, time);
    }

    private enum ElevationKind
    {
        StandardUser,
        Limited,
        Elevated,
    }

    private static ElevationKind Elevation()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out var token)) return ElevationKind.StandardUser;
        try
        {
            var elevated = GetTokenInformation(token, TokenElevation, out var isElevated, sizeof(uint), out _)
                           && isElevated != 0;
            if (elevated) return ElevationKind.Elevated;
            if (GetTokenInformation(token, TokenElevationType, out var type, sizeof(uint), out _)
                && type == TokenElevationTypeLimited)
                return ElevationKind.Limited;
            return ElevationKind.StandardUser;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static Task<T> RunOnStaThreadAsync<T>(Func<T> work)
    {
        var done = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try { done.SetResult(work()); }
            catch (Exception e) { done.SetException(e); }
        })
        {
            IsBackground = true,
            Name = "purge-broker-launch",
        };
        if (OperatingSystem.IsWindows()) thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        return done.Task;
    }

    private static unsafe ShellLaunch RunShell(string brokerPath, string arguments, string directory, nint ownerWindow)
    {
        var size = (uint)sizeof(ShellExecuteInfo);
        fixed (char* verb = "runas")
        fixed (char* file = brokerPath)
        fixed (char* parameters = arguments)
        fixed (char* workDirectory = directory)
        {
            var info = new ShellExecuteInfo
            {
                cbSize = size,
                fMask = SeeMaskNoCloseProcess | SeeMaskNoAsync,
                hwnd = ownerWindow,
                lpVerb = verb,
                lpFile = file,
                lpParameters = parameters,
                lpDirectory = workDirectory,
                nShow = SwHide,
            };
            if (!ShellExecuteEx(&info))
                return new ShellLaunch(false, Marshal.GetLastWin32Error(), 0);
            return new ShellLaunch(true, 0, info.hProcess);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct ShellExecuteInfo
    {
        public uint cbSize;
        public uint fMask;
        public nint hwnd;
        public char* lpVerb;
        public char* lpFile;
        public char* lpParameters;
        public char* lpDirectory;
        public int nShow;
        public nint hInstApp;
        public nint lpIDList;
        public char* lpClass;
        public nint hkeyClass;
        public uint dwHotKey;
        public nint hIcon;
        public nint hProcess;
    }

    private readonly record struct ShellLaunch(bool Ok, int Error, nint Process);

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
    }

    [LibraryImport("shell32.dll", EntryPoint = "ShellExecuteExW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool ShellExecuteEx(ShellExecuteInfo* info);

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(nint process, out FileTime creation, out FileTime exit, out FileTime kernel,
        out FileTime user);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint GetProcessId(nint process);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetExitCodeProcess(nint process, out int exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial uint WaitForSingleObject(nint handle, uint milliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool TerminateProcess(nint process, uint exitCode);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool OpenProcessToken(nint process, uint access, out nint token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetTokenInformation(nint token, int infoClass, out uint info, uint length, out uint returned);

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CloseHandle(nint handle);
}
