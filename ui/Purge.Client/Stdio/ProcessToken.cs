using System.Runtime.InteropServices;

namespace Purge.Client;

/// <summary>Facts about this process's own token.</summary>
public static partial class ProcessToken
{
    private const uint TokenQuery = 0x8;
    private const int TokenElevation = 20;

    /// <summary>True when this process runs elevated (started "as administrator", or UAC is off for an administrator).</summary>
    public static bool IsElevated()
    {
        if (!OperatingSystem.IsWindows()) return false;
        if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out var token)) return false;
        try
        {
            return GetTokenInformation(token, TokenElevation, out var elevated, sizeof(uint), out _) && elevated != 0;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

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
