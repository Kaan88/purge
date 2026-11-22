using System.Runtime.InteropServices;
using System.Text;

namespace Purge.App;

/// <summary>
/// Launch markers relative to process creation (ENGINE_PLAN.md §9.2, measurement (a)). Each marker is the
/// time in milliseconds since the kernel created this process. When <c>PURGE_BENCH_OUT</c> names a file, the
/// markers are appended to it as one line per launch once the first frame has been presented.
/// Off the bench (<see cref="Enabled"/> false) <see cref="Mark"/> costs one branch and records nothing.
/// TraceLogging output comes later.
/// </summary>
public static partial class LaunchMarkers
{
    /// <summary>True when <c>PURGE_BENCH_OUT</c> names a file: the launch bench, and only then, keeps markers.</summary>
    public static readonly bool Enabled = !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PURGE_BENCH_OUT"));

    private static readonly List<(string Name, double Ms)> Marks = [];
    private static readonly Lock Gate = new();
    private static long CreationFileTime;

    static LaunchMarkers()
    {
        // Read the process creation time once, and only for a bench launch.
        if (Enabled) CreationFileTime = GetCreationTime();
    }

    /// <summary>The first marker: runs when the assembly loads, before <c>Main</c>.</summary>
    [System.Runtime.CompilerServices.ModuleInitializer]
    internal static void ModuleInit() => Mark("module_init");

    public static double Mark(string name)
    {
        if (!Enabled) return 0;
        GetSystemTimePreciseAsFileTime(out var now);
        var ms = (now - CreationFileTime) / 10_000.0;
        lock (Gate) Marks.Add((name, ms));
        return ms;
    }

    /// <summary>Records <paramref name="name"/> at an earlier marker's time (<c>names_visible</c> when the rows were in the
    /// first presented frame).</summary>
    public static void Record(string name, double ms)
    {
        if (!Enabled) return;
        lock (Gate) Marks.Add((name, ms));
    }

    public static IReadOnlyList<(string Name, double Ms)> Snapshot()
    {
        lock (Gate) return Marks.ToArray();
    }

    public static double? Get(string name)
    {
        lock (Gate)
            foreach (var (n, ms) in Marks)
                if (n == name) return ms;
        return null;
    }

    public static string Format()
    {
        var sb = new StringBuilder();
        foreach (var (n, ms) in Snapshot())
            sb.Append(n).Append('=').Append(ms.ToString("F1", System.Globalization.CultureInfo.InvariantCulture)).Append(' ');
        return sb.ToString().TrimEnd();
    }

    public static void Flush()
    {
        var path = Environment.GetEnvironmentVariable("PURGE_BENCH_OUT");
        if (string.IsNullOrEmpty(path)) return;
        try { File.AppendAllText(path, Format() + Environment.NewLine); }
        catch (IOException) { }
    }

    private static long GetCreationTime()
    {
        GetProcessTimes(GetCurrentProcess(), out var creation, out _, out _, out _);
        return creation;
    }

    [LibraryImport("kernel32.dll")]
    private static partial nint GetCurrentProcess();

    [LibraryImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetProcessTimes(nint process, out long creation, out long exit, out long kernel, out long user);

    [LibraryImport("kernel32.dll")]
    private static partial void GetSystemTimePreciseAsFileTime(out long fileTime);

    [LibraryImport("dwmapi.dll")]
    internal static partial int DwmFlush();
}
