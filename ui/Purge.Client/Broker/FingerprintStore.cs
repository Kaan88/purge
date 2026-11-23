using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Purge.Client.Broker;

/// <summary>
/// The medium side's only look at the broker's fingerprint store, <c>%ProgramData%\Purge\fp</c>: whether a stored
/// fingerprint may exist for a program, so the Programs page offers "Check for leftovers" (and the Windows prompt it
/// needs) only for a program Purge recorded (M3 design 7a delta 5; DECISIONS 2026-11-23 "removed outside Purge").
/// <para>
/// <c>fp</c> and its files are admin-only (<c>Store</c> and <c>StoreFile</c> descriptors: SYSTEM and Administrators,
/// no entry for Users), so this process can never open or read a fingerprint. It asks Windows for the attributes of
/// the one name the broker would use (<c>fp-&lt;SHA-256 of the program id, lower-case hex&gt;.json</c>, as
/// <c>fingerprint_name</c> in <c>bins/purge-broker/src/uninstall.rs</c>): with "bypass traverse checking" the lookup
/// answers "not found" for a name that is not there and "access denied" for one that is. Only a definite "not found"
/// (the file, or <c>fp</c> itself) counts as no record; any other answer may be a record, and the broker's
/// <c>leftovers.stored</c> decides after the prompt. Nothing here reads content, and nothing it says is trusted
/// beyond showing or hiding a button.
/// </para>
/// </summary>
public static partial class FingerprintStore
{
    private const uint InvalidFileAttributes = 0xFFFF_FFFF;
    private const int ErrorFileNotFound = 2;
    private const int ErrorPathNotFound = 3;

    /// <summary><c>%ProgramData%\Purge\fp</c>, or "" when Windows names no ProgramData folder.</summary>
    public static string DefaultDirectory()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return programData.Length == 0 ? "" : Path.Combine(programData, "Purge", "fp");
    }

    /// <summary>The broker's file name for <paramref name="programId"/>: <c>fp-</c>, SHA-256 of its UTF-8 bytes in lower-case hex, <c>.json</c>.</summary>
    public static string FileName(string programId) =>
        "fp-" + Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(programId))) + ".json";

    /// <summary>
    /// False only when Windows says the fingerprint file (or the store directory) does not exist; true otherwise,
    /// including when it exists but cannot be read, and on any error. <paramref name="directory"/> is for the tests.
    /// </summary>
    public static bool MayHaveRecord(string programId, string? directory = null)
    {
        if (!OperatingSystem.IsWindows()) return true;
        var dir = directory ?? DefaultDirectory();
        if (dir.Length == 0) return true;
        if (GetFileAttributes(Path.Combine(dir, FileName(programId))) != InvalidFileAttributes) return true;
        return Marshal.GetLastPInvokeError() is not (ErrorFileNotFound or ErrorPathNotFound);
    }

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileAttributesW", SetLastError = true,
        StringMarshalling = StringMarshalling.Utf16)]
    private static partial uint GetFileAttributes(string path);
}
