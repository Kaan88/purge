using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Purge.Client.Broker;

/// <summary>What the client found at the other end of the pipe.</summary>
public enum BrokerServerCheckStatus
{
    /// <summary>The server is the process the launcher started, from the expected image, running elevated.</summary>
    Ok,

    /// <summary><c>GetNamedPipeServerProcessId</c> named another process than the one <c>ShellExecuteExW</c> returned.</summary>
    PidMismatch,

    /// <summary>The server process's image is not the broker executable that was launched.</summary>
    ImageMismatch,

    /// <summary>The server process's token is not elevated.</summary>
    NotElevated,

    /// <summary>The server process could not be queried (ended, or access refused).</summary>
    CannotQuery,
}

/// <summary>The answer of <see cref="BrokerServerCheck.Check"/>; <see cref="Reason"/> is a sentence for the UI.</summary>
public sealed record BrokerServerCheckResult(BrokerServerCheckStatus Status, string Reason)
{
    public bool Ok => Status == BrokerServerCheckStatus.Ok;

    internal static BrokerServerCheckResult Pass() => new(BrokerServerCheckStatus.Ok, "");
}

/// <summary>
/// The client's half of design 3.3 step 3: before the UI sends anything, the server end of the pipe must be the
/// process <c>ShellExecuteExW</c> returned, its image must be the broker that was started, and its token must be
/// elevated. The broker sends nothing to a refused client, so this check is the UI's own guarantee that it is
/// talking to the administrator part and not to a squatter that won the pipe name.
/// </summary>
public static partial class BrokerServerCheck
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x8;
    private const int TokenElevation = 20;
    private const int ErrorInsufficientBuffer = 122;

    /// <summary>
    /// Checks the server behind <paramref name="pipe"/> (a connected client end of a named pipe).
    /// </summary>
    /// <param name="pipe">The client end, before the client has written anything.</param>
    /// <param name="expectedPid">The pid of the process <c>ShellExecuteExW</c> returned.</param>
    /// <param name="expectedImagePath">The broker executable that was launched.</param>
    /// <param name="requireElevation">False only for tests that cannot be elevated; the product always passes true.</param>
    public static BrokerServerCheckResult Check(SafeHandle pipe, int expectedPid, string expectedImagePath,
        bool requireElevation = true)
    {
        if (!OperatingSystem.IsWindows())
            return new(BrokerServerCheckStatus.CannotQuery, "The administrator part is a Windows program.");
        if (!GetNamedPipeServerProcessId(pipe.DangerousGetHandle(), out var serverPid))
        {
            var error = Marshal.GetLastWin32Error();
            return new(BrokerServerCheckStatus.CannotQuery,
                "Purge could not tell which program is on its pipe: " + Describe(error));
        }
        if (serverPid != (uint)expectedPid)
            return new(BrokerServerCheckStatus.PidMismatch,
                "The program on Purge's pipe is not the administrator part Purge started.");

        var raw = OpenProcess(ProcessQueryLimitedInformation, false, serverPid);
        if (raw == 0)
        {
            var error = Marshal.GetLastWin32Error();
            return new(BrokerServerCheckStatus.CannotQuery,
                "Purge could not open the administrator part: " + Describe(error));
        }
        using var process = new SafeProcessHandle(raw, ownsHandle: true);

        var image = ImagePath(process);
        if (image is null)
            return new(BrokerServerCheckStatus.CannotQuery, "Purge could not read the administrator part's image.");
        if (!string.Equals(image, expectedImagePath, StringComparison.OrdinalIgnoreCase))
            return new(BrokerServerCheckStatus.ImageMismatch,
                "The program on Purge's pipe is not the administrator part Purge started.");

        if (requireElevation && !IsElevated(process))
            return new(BrokerServerCheckStatus.NotElevated,
                "The administrator part is not running with administrator permission.");

        return BrokerServerCheckResult.Pass();
    }

    private static string? ImagePath(SafeProcessHandle process)
    {
        for (var size = 1024; size <= 64 * 1024; size *= 2)
        {
            var buffer = new char[size];
            uint length = (uint)size;
            unsafe
            {
                fixed (char* text = buffer)
                {
                    if (QueryFullProcessImageNameW(process.DangerousGetHandle(), 0, text, ref length))
                        return new string(text, 0, (int)length);
                }
            }
            if (Marshal.GetLastWin32Error() != ErrorInsufficientBuffer) return null;
        }
        return null;
    }

    private static bool IsElevated(SafeProcessHandle process)
    {
        if (!OpenProcessToken(process.DangerousGetHandle(), TokenQuery, out var token)) return false;
        try
        {
            return GetTokenInformation(token, TokenElevation, out var elevated, sizeof(uint), out _) && elevated != 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static string Describe(int error) => new Win32Exception(error).Message;

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetNamedPipeServerProcessId(nint pipe, out uint serverProcessId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    private static partial nint OpenProcess(uint access, [MarshalAs(UnmanagedType.Bool)] bool inherit, uint processId);

    [LibraryImport("kernel32.dll", EntryPoint = "QueryFullProcessImageNameW", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static unsafe partial bool QueryFullProcessImageNameW(nint process, uint flags, char* name, ref uint size);

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
