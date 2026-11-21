using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Purge.Client;
using Purge.Client.Model;

namespace Purge.App;

/// <summary>
/// Custom entry point (ENGINE_PLAN.md §9.2 step 1). The engine request goes out before XAML starts so the
/// program list is usually ready by the time the window is built.
/// </summary>
public static class Program
{
    /// <summary>The engine connection (the sample-data stub until the JSON-RPC client lands).</summary>
    public static IEngineClient Engine { get; private set; } = null!;

    /// <summary><c>engine.hello</c> + <c>programs.list</c>, started before XAML init.</summary>
    public static Task<StartupData> Startup { get; private set; } = null!;

    public static StartupOptions Options { get; private set; } = new();

    [STAThread]
    private static int Main(string[] args)
    {
        LaunchMarkers.Mark("main");
        Options = StartupOptions.Parse(args);

        // (a) "Always start elevated" re-exec goes here (setting not implemented yet).
        // (b) The engine link. Until the stdio JSON-RPC client lands (M3-RPC-CLIENT) every run uses the sample-data
        //     stub, with or without --sample; the one-process-per-verb CLI client is a test helper only.
        Engine = new FakeEngineClient();
        // (c) Send engine.hello + programs.list; read on a background thread.
        Startup = Task.Run(async () =>
        {
            var hello = await Engine.HelloAsync().ConfigureAwait(false);
            var doc = await Engine.ListProgramsAsync().ConfigureAwait(false);
            LaunchMarkers.Mark("list_reply");
            return new StartupData(hello, doc);
        });

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

public sealed record StartupData(EngineHello Hello, InventoryDoc Inventory, string? Error = null);

/// <summary>Command-line switches for development and the launch bench.</summary>
public sealed class StartupOptions
{
    /// <summary><c>--theme light|dark</c>: overrides the system theme for this run.</summary>
    public ElementTheme Theme { get; private init; } = ElementTheme.Default;

    /// <summary><c>--page key</c>: open on another screen (programs, queue, leftovers, history, vault, settings).</summary>
    public string? Page { get; private init; }

    /// <summary><c>--bench-exit</c>: close the window after the first presented frame (launch bench).</summary>
    public bool BenchExit { get; private init; }

    /// <summary><c>--sample</c>: use the sample data (the only mode until the JSON-RPC client lands).</summary>
    public bool Sample { get; private init; }

    public static StartupOptions Parse(string[] args)
    {
        var theme = ElementTheme.Default;
        var benchExit = false;
        var sample = false;
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
                case "--sample":
                    sample = true;
                    break;
            }
        }
        return new StartupOptions { Theme = theme, BenchExit = benchExit, Page = page, Sample = sample };
    }
}
