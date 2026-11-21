using System.IO.Pipes;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Purge.Client.Broker;

/// <summary>The answer of <see cref="BrokerPipe.TryOpen"/>.</summary>
public sealed class BrokerPipeOpen : IDisposable
{
    private BrokerPipeOpen(NamedPipeClientStream? stream, BrokerServerCheckResult? check, int win32Error)
    {
        Stream = stream;
        Check = check;
        Win32Error = win32Error;
    }

    /// <summary>The connected duplex stream, set only when the server check passed.</summary>
    public NamedPipeClientStream? Stream { get; private set; }

    /// <summary>The failed server check; null when the pipe could not be opened or the check passed.</summary>
    public BrokerServerCheckResult? Check { get; }

    /// <summary>The <c>CreateFileW</c> error when the pipe could not be opened, or 0.</summary>
    public int Win32Error { get; }

    /// <summary>The stream, handed to the caller, which then owns it.</summary>
    public NamedPipeClientStream TakeStream()
    {
        var stream = Stream ?? throw new InvalidOperationException("the pipe is not open");
        Stream = null;
        return stream;
    }

    public void Dispose() => Stream?.Dispose();

    internal static BrokerPipeOpen Opened(NamedPipeClientStream stream) => new(stream, null, 0);

    internal static BrokerPipeOpen CheckFailed(BrokerServerCheckResult check) => new(null, check, 0);

    internal static BrokerPipeOpen Unavailable(int win32Error) => new(null, null, win32Error);
}

/// <summary>
/// Opens the broker's pipe the one way that works. The handle is overlapped (<c>FILE_FLAG_OVERLAPPED</c>): the
/// reader thread sits in a read for the whole life of the link, and Windows serialises I/O on a synchronous handle,
/// so a write (<c>engine.hello</c> first, and the broker sends nothing before it) would wait behind that read for
/// ever (review M3-R2 B2). The wrapping <see cref="NamedPipeClientStream"/> allows one reader and one writer at a
/// time. The server check runs on the raw handle before any byte is written, and the handle is opened with
/// <c>SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION</c> so the broker can identify the client before its first write.
/// </summary>
public static partial class BrokerPipe
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint SecuritySqosPresent = 0x00100000;
    private const uint SecurityIdentification = 0x00010000;

    private const uint ClientFlags = FileAttributeNormal | FileFlagOverlapped | SecuritySqosPresent | SecurityIdentification;

    /// <summary>
    /// One attempt to open <paramref name="path"/> and check its server. On a failed check the handle is closed and
    /// nothing was written.
    /// </summary>
    /// <param name="path">The pipe path, <c>\\.\pipe\purge-...</c>.</param>
    /// <param name="expectedPid">The pid of the process <c>ShellExecuteExW</c> returned.</param>
    /// <param name="expectedImagePath">The broker executable that was launched.</param>
    /// <param name="requireElevation">False only for tests that cannot be elevated; the product always passes true.</param>
    public static BrokerPipeOpen TryOpen(string path, int expectedPid, string expectedImagePath, bool requireElevation = true)
    {
        var raw = CreateFile(path, GenericRead | GenericWrite, FileShareRead | FileShareWrite, 0, OpenExisting, ClientFlags, 0);
        if (raw == -1 || raw == 0) return BrokerPipeOpen.Unavailable(Marshal.GetLastWin32Error());

        var handle = new SafePipeHandle(raw, ownsHandle: true);
        try
        {
            var check = BrokerServerCheck.Check(handle, expectedPid, expectedImagePath, requireElevation);
            if (!check.Ok)
            {
                handle.Dispose();
                return BrokerPipeOpen.CheckFailed(check);
            }
            // The stream takes ownership of the handle; closing the stream closes the client end.
            return BrokerPipeOpen.Opened(new NamedPipeClientStream(PipeDirection.InOut, isAsync: true, isConnected: true, handle));
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial nint CreateFile(string fileName, uint access, uint share, nint security, uint creation,
        uint flags, nint template);
}
