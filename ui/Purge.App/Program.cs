using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Settings;
using Purge.Client;
using Purge.Client.Stdio;

namespace Purge.App;

/// <summary>
/// Custom entry point (ENGINE_PLAN.md §9.2 step 1). The engine request goes out before XAML starts so the
/// program list is usually ready by the time the window is built.
/// </summary>
public static class Program
{
    private static EngineLink _link = null!;

    /// <summary>The engine connection; the sample-data stub when the engine is not used or could not be.</summary>
    public static IEngineClient Engine => _link.Client;

    /// <summary><c>engine.hello</c> + <c>programs.list</c>, started before XAML init.</summary>
    public static Task<StartupResult> Startup { get; private set; } = null!;

    /// <summary>The rows of the <see cref="Startup"/> list, built off the UI thread when the reply comes in.</summary>
    public static Task<Views.ProgramsView.PreparedList> Prepared { get; private set; } = null!;

    /// <summary>Next to <c>Purge.exe</c>, or the file named by <c>PURGE_ENGINE</c> (development).</summary>
    private static string EnginePath() =>
        Environment.GetEnvironmentVariable("PURGE_ENGINE") is { Length: > 0 } path ? path : Path.Combine(AppContext.BaseDirectory, "purge-engine.exe");

    public static StartupOptions Options { get; private set; } = new();

    [STAThread]
    private static int Main(string[] args)
    {
        LaunchMarkers.Mark("main");
        try
        {
            Options = StartupOptions.Parse(args);
        }
        catch (ArgumentException e)
        {
            // A WinExe has no console by default; a dev console and the bench see the exit code instead.
            Console.Error.WriteLine($"purge: {e.Message}");
            return 2;
        }

        // (a) "Always start elevated" re-exec goes here (setting not implemented yet; it moves to M4).
        // (b) The engine link: purge-engine --stdio in a kill-on-close job with two inherited pipes. --sample and
        //     --bench-stub (the launch bench) use the sample-data stub instead; so does a missing or failing engine,
        //     with a notice. The broker and UAC are never touched here.
        // (c) engine.hello + programs.list are sent and read on a background thread.
        _link = new EngineLink(
            open: () => StdioEngineClient.Start(EnginePath()),
            fallback: () => new FakeEngineClient { BenchRows = Options.BenchStub ? 300 : 0 },
            sample: Options.Sample || Options.BenchStub,
            engineReady: () => LaunchMarkers.Mark("engine_ready"),
            listReply: () => LaunchMarkers.Mark("list_reply"));
        Startup = _link.Startup;
        // The rows are built and sorted on the thread that read the reply, not on the UI thread (M3 launch perf).
        // ExecuteSynchronously: Prepare runs on the engine reply thread (the pool thread that completes Startup), or
        // here in Main when the reply is already in, before or while the window is built; the first culture-aware
        // sort also loads ICU there. When the window takes the reply before Prepared has finished,
        // MainWindow.OnStartup passes no prepared list and the UI thread builds the rows itself (ProgramsView.Load),
        // as before this change.
        Prepared = Startup.ContinueWith(t => Views.ProgramsView.Prepare(t.Result.Inventory), CancellationToken.None,
            TaskContinuationOptions.OnlyOnRanToCompletion | TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);

        // (d) The XAML optional changes under test (ENGINE_PLAN.md §9.2 step 8); none is on by default.
        // OptimizeApplyStyles is refused: it stays off on Windows App SDK 2.6.5 (ContentDialog regression).
        foreach (var change in Options.XamlChanges)
        {
            switch (change)
            {
                case "DefaultStyleOptimizations":
                    XamlOptionalChanges.EnableChange(XamlChangeId.DefaultStyleOptimizations);
                    break;
                case "IconNoGridOptimization":
                    XamlOptionalChanges.EnableChange(XamlChangeId.IconNoGridOptimization);
                    break;
                case "DeferContextFlyoutInit":
                    XamlOptionalChanges.EnableChange(XamlChangeId.DeferContextFlyoutInit);
                    break;
            }
        }

        // (e) Start XAML.
        WinRT.ComWrappersSupport.InitializeComWrappers();
        Application.Start(p =>
        {
            var context = new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread());
            SynchronizationContext.SetSynchronizationContext(context);
            _ = new App();
        });
        return 0;
    }
}

/// <summary>Command-line switches for development and the launch bench.</summary>
public sealed class StartupOptions
{
    /// <summary><c>--theme light|dark</c>: overrides the system theme for this run.</summary>
    public ElementTheme Theme { get; private init; } = ElementTheme.Default;

    /// <summary><c>--page key</c>: open on another screen (programs, queue, leftovers, history, vault, settings).</summary>
    public string? Page { get; private init; }

    /// <summary><c>--bench-exit</c>: close the window after the first presented frame (launch bench).</summary>
    public bool BenchExit { get; private init; }

    /// <summary><c>--sample</c>: use the sample data without starting the engine.</summary>
    public bool Sample { get; private init; }

    /// <summary><c>--bench-stub</c>: the stub engine answers <c>programs.list</c> with 300 rows after 20 ms (launch bench).</summary>
    public bool BenchStub { get; private init; }

    /// <summary><c>--xaml-changes A,B</c>: XAML optional changes to enable (launch bench; the three of §9.2 step 8 only).</summary>
    public IReadOnlyList<string> XamlChanges { get; private init; } = [];

    /// <summary>
    /// <c>--bench-until marker</c>: the launch marker after which the bench writes its line (and, with <c>--bench-exit</c>,
    /// closes): <c>presented</c> (default), <c>names_visible</c>, <c>icons_visible</c> or <c>s3_open</c>.
    /// </summary>
    public string BenchUntil { get; private init; } = "presented";

    /// <summary><c>--bench-s3 N</c>: after the first frame, open the Leftovers page (S3) on an N-item sample fixture and
    /// mark <c>s3_start</c> and <c>s3_open</c> (launch bench, M3 design 9.1). Needs <c>--bench-stub</c>.</summary>
    public int BenchS3Items { get; private init; }

    /// <summary>The markers <c>--bench-until</c> accepts.</summary>
    private static readonly string[] BenchEnds = ["presented", "names_visible", "icons_visible", "s3_open"];

    /// <summary>The XAML optional changes the bench may try, one at a time (ENGINE_PLAN.md §9.2 step 8).</summary>
    private static readonly string[] XamlChangeNames =
    [
        "DefaultStyleOptimizations",
        "IconNoGridOptimization",
        "DeferContextFlyoutInit",
    ];

    public static StartupOptions Parse(string[] args)
    {
        var theme = ElementTheme.Default;
        var benchExit = false;
        var sample = false;
        var benchStub = false;
        var benchUntil = "presented";
        var benchS3 = 0;
        IReadOnlyList<string> xamlChanges = [];
        string? page = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--theme" when i + 1 < args.Length:
                    theme = args[++i] switch
                    {
                        "light" => ElementTheme.Light,
                        "dark" => ElementTheme.Dark,
                        _ => ElementTheme.Default,
                    };
                    break;
                case "--page" when i + 1 < args.Length:
                    page = args[++i];
                    break;
                case "--bench-exit":
                    benchExit = true;
                    break;
                case "--xaml-changes" when i + 1 < args.Length:
                    xamlChanges = args[++i].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    foreach (var change in xamlChanges)
                        if (!XamlChangeNames.Contains(change, StringComparer.Ordinal))
                            throw new ArgumentException(change == "OptimizeApplyStyles"
                                ? "--xaml-changes OptimizeApplyStyles stays off on Windows App SDK 2.6.5 (ContentDialog regression)"
                                : $"--xaml-changes has no change named '{change}'");
                    break;
                case "--xaml-changes":
                    throw new ArgumentException("--xaml-changes needs a comma-separated value");
                case "--bench-stub":
                    benchStub = true;
                    break;
                case "--bench-until" when i + 1 < args.Length:
                    benchUntil = args[++i];
                    if (!BenchEnds.Contains(benchUntil, StringComparer.Ordinal))
                        throw new ArgumentException($"--bench-until takes one of {string.Join(", ", BenchEnds)}, not '{benchUntil}'");
                    break;
                case "--bench-until":
                    throw new ArgumentException("--bench-until needs a marker name");
                case "--bench-s3" when i + 1 < args.Length:
                    if (!int.TryParse(args[++i], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out benchS3) || benchS3 < 1)
                        throw new ArgumentException("--bench-s3 needs a positive item count");
                    break;
                case "--bench-s3":
                    throw new ArgumentException("--bench-s3 needs an item count");
                case "--sample":
                    sample = true;
                    break;
            }
        }
        // The fixture is the sample client's page: with the real engine S3 would show "No scan yet" and never open.
        if (benchS3 > 0 && !benchStub)
            throw new ArgumentException("--bench-s3 needs --bench-stub");
        return new StartupOptions
        {
            Theme = theme, BenchExit = benchExit, Page = page, Sample = sample, BenchStub = benchStub, XamlChanges = xamlChanges,
            BenchUntil = benchUntil, BenchS3Items = benchS3,
        };
    }
}
