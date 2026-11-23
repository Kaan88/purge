using System.Runtime.InteropServices;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Purge.App.Shell;
using Purge.App.Views;
using Purge.Client;
using Windows.Graphics;

namespace Purge.App;

public sealed partial class MainWindow : Window
{
    public static MainWindow Instance { get; private set; } = null!;

    private readonly ProgramsView _programs;
    private readonly Dictionary<string, UIElement> _views = new();
    private readonly (Button Button, Border Selection, Border Pill)[] _rail;
    private bool _firstTickSeen;

    public MainWindow()
    {
        Instance = this;
        InitializeComponent();
        LaunchMarkers.Mark("window_ctor");

        SystemBackdrop = new MicaBackdrop();
        LaunchMarkers.Mark("w_backdrop");
        var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "Purge.ico");
        if (File.Exists(icon)) AppWindow.SetIcon(icon);
        LaunchMarkers.Mark("w_icon");
        SizeAndCenter(1360, 860);
        LaunchMarkers.Mark("w_size");
        ApplyTheme(Program.Options.Theme);

        _rail =
        [
            (NavPrograms, SelPrograms, PillPrograms), (NavQueue, SelQueue, PillQueue),
            (NavLeftovers, SelLeftovers, PillLeftovers), (NavHistory, SelHistory, PillHistory),
            (NavVault, SelVault, PillVault), (NavSettings, SelSettings, PillSettings),
        ];

        // S1 is the only view built for the first frame; its rows are set before Activate() when the list
        // reply is already in (§9.2 step 4).
        _programs = new ProgramsView();
        LaunchMarkers.Mark("programs_ctor");
        _views["programs"] = _programs;
        ContentCard.Child = _programs;
        var loaded = Program.Startup.IsCompletedSuccessfully;
        if (loaded) OnStartup(Program.Startup.Result);

        if (Program.Options.Page is { } page) Navigate(page);
        if (loaded) LaunchMarkers.Mark("rows_set");

        // The title bar goes last (M3 launch perf): the first ExtendsContentIntoTitleBar call waits until the
        // window's composition is ready (about 200 ms after start on the bench laptop, the same wait the bare
        // control pays in its first frame). Everything above runs before that wait ends instead of after it.
        // It is still before Activate(), so the window never shows the system caption.
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        LaunchMarkers.Mark("w_titlebar");
        // A list reply that came in during that wait still makes the first frame.
        if (!loaded)
        {
            if (Program.Startup.IsCompletedSuccessfully) OnStartup(Program.Startup.Result);
            else _ = LoadWhenReadyAsync();
            LaunchMarkers.Mark("rows_set");
        }
        CompositionTarget.Rendering += OnFirstRendering;
        // No engine outlives the window: the client ends what it runs and closes its kill-on-close job.
        Closed += (_, _) => Program.Engine.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    private async Task LoadWhenReadyAsync() => OnStartup(await Program.Startup);

    private void OnStartup(StartupResult data)
    {
        _programs.Load(data);
        // The "Administrator" chip shows only when the UI itself runs elevated (7a delta 2); the token is read
        // off the UI thread, so it also holds when the engine is not used.
        ElevationChip.Visibility = data.UiElevated ? Visibility.Visible : Visibility.Collapsed;
        if (data.Error is { } error)
        {
            // The bench's --real-engine mode refuses a run whose list is the sample data.
            LaunchMarkers.Mark("engine_fallback");
            _programs.ShowEngineNotice(error);
        }
    }

    private StackPanel? _barHost;

    /// <summary>Explains the Windows admin prompt the first time; false when the user chose "Not now".</summary>
    public Task<bool> ConfirmFirstElevationAsync() => ElevationPrompts.ConfirmFirstElevationAsync(Root.XamlRoot, Root.ActualTheme);

    /// <summary>Shows the "You cancelled the admin prompt" bar over the top of the page (built on first use).</summary>
    public void ShowAdminPromptCancelled(Action? tryAgain = null)
    {
        if (_barHost is null && ContentCard.Parent is Grid grid)
        {
            _barHost = new StackPanel { VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(16, 12, 16, 0), Spacing = 8 };
            Grid.SetColumn(_barHost, 1);
            grid.Children.Add(_barHost);
        }
        if (_barHost is null) return;
        _barHost.Children.Clear();
        var bar = ElevationPrompts.CancelledBar(Root.ActualTheme, tryAgain);
        bar.Closed += (s, _) => _barHost.Children.Remove(s);
        _barHost.Children.Add(bar);
    }

    /// <summary>The S3 review page (built on first use); the Uninstall pipeline hands it the scan.</summary>
    public LeftoversView OpenReview()
    {
        Navigate("leftovers");
        return (LeftoversView)_views["leftovers"];
    }

    /// <summary>S2, built on first use; the Uninstall click on Programs starts its pipeline.</summary>
    public UninstallView OpenUninstall()
    {
        Navigate("queue");
        return (UninstallView)_views["queue"];
    }

    /// <summary>The XamlRoot a dialog of a page uses (null before the window is loaded).</summary>
    public XamlRoot? DialogRoot => Root.XamlRoot;

    private void OnFirstRendering(object? sender, object e)
    {
        if (_firstTickSeen) return;
        _firstTickSeen = true;
        CompositionTarget.Rendering -= OnFirstRendering;
        LaunchMarkers.Mark("first_tick");

        // Approximate "first presented frame": the next DWM composition after the first tick has been committed.
        // The precise number comes from Dwm-Core present events in WPR (§9.2 (a)).
        // In a bench run the flush runs on this thread before the deferred first-tick work, so the marker
        // times the frame that carries the first tick, not the work that follows it. A normal run does not
        // pay for the one-frame wait (its markers are off, see LaunchMarkers.Enabled).
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
        {
            if (LaunchMarkers.Enabled)
            {
                LaunchMarkers.DwmFlush();
                LaunchMarkers.Mark("presented");
                _programs.OnPresented();
            }
            // With the default --bench-until presented this writes the line and queues the exit, as before.
            BenchReached("presented");
            _programs.OnFirstTick();
            if (_benchDone && Program.Options.BenchExit) return;
            DispatcherQueue.TryEnqueue(() => _programs.ShowLaunchTime());
            if (Program.Options.BenchExit) StartBenchTimeout();
            if (Program.Options.BenchS3Items > 0)
                DispatcherQueue.TryEnqueue(() =>
                {
                    LaunchMarkers.Mark("s3_start");
                    Navigate("leftovers");
                });
        });
    }

    private bool _benchDone;
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _benchTimer;

    /// <summary>A later bench marker the app waits for (<c>--bench-until</c>) gets at most this long after the first frame.</summary>
    private static readonly TimeSpan BenchTimeout = TimeSpan.FromSeconds(20);

    /// <summary>
    /// Marks <paramref name="name"/> after the next DWM composition (the same approximation as <c>presented</c>), then
    /// tells <see cref="BenchReached"/>. A no-op off the bench.
    /// </summary>
    public void MarkAfterNextFrame(string name)
    {
        if (!LaunchMarkers.Enabled) return;
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
        {
            LaunchMarkers.DwmFlush();
            LaunchMarkers.Mark(name);
            BenchReached(name);
        });
    }

    /// <summary>
    /// The bench end: when <paramref name="name"/> is the <c>--bench-until</c> marker, writes the marker line once and,
    /// with <c>--bench-exit</c>, closes the app. A live engine's icon load is let finish first (at most 10 s) so the
    /// icon atlas is saved and the next launch finds a warm cache.
    /// </summary>
    public void BenchReached(string name)
    {
        if (_benchDone || name != Program.Options.BenchUntil) return;
        _benchDone = true;
        LaunchMarkers.Flush();
        if (Program.Options.BenchExit) _ = ExitAfterIconsAsync();
    }

    private async Task ExitAfterIconsAsync()
    {
        if (Program.Engine.IsLive) await Task.WhenAny(_programs.IconsDone, Task.Delay(TimeSpan.FromSeconds(10)));
        // Close runs the Closed handler (engine disposal); Exit ends Application.Start, which closing the last
        // window does not do on its own for an unpackaged app.
        DispatcherQueue.TryEnqueue(() => { Close(); Application.Current.Exit(); });
    }

    /// <summary>A bench run whose <c>--bench-until</c> marker never comes writes what it has and ends.</summary>
    private void StartBenchTimeout()
    {
        // Kept in a field: a DispatcherQueueTimer nobody references can be collected before it fires.
        var timer = _benchTimer = DispatcherQueue.CreateTimer();
        timer.Interval = BenchTimeout;
        timer.IsRepeating = false;
        timer.Tick += (_, _) =>
        {
            if (_benchDone) return;
            LaunchMarkers.Mark("bench_timeout");
            BenchReached(Program.Options.BenchUntil);
        };
        timer.Start();
    }

    private void OnRailClick(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string key }) Navigate(key);
    }

    /// <summary>S1, built for the first frame and kept.</summary>
    public ProgramsView Programs => _programs;

    /// <summary>The view shown in the content card.</summary>
    public UIElement? CurrentView => ContentCard.Child;

    /// <summary>The page shown, by rail key.</summary>
    public string CurrentPage { get; private set; } = "programs";

    public void Navigate(string key)
    {
        if (!_views.TryGetValue(key, out var view))
        {
            view = key switch
            {
                "queue" => new UninstallView(),
                "leftovers" => new LeftoversView(),
                "vault" => new VaultView(),
                "history" => new HistoryView(),
                "settings" => new SettingsView(),
                _ => _programs,
            };
            _views[key] = view;
        }
        ContentCard.Child = view;
        foreach (var (button, selection, pill) in _rail)
        {
            var visibility = button.Tag as string == key ? Visibility.Visible : Visibility.Collapsed;
            selection.Visibility = visibility;
            pill.Visibility = visibility;
        }
        CurrentPage = key;
        if (Root.RequestedTheme != ElementTheme.Default)
            DispatcherQueue.TryEnqueue(() => PinInfoBars(view));
    }

    /// <summary>The theme the window shows (Settings → Appearance, else Windows).</summary>
    public ElementTheme ActualTheme => Root.ActualTheme;

    // InfoBar takes its severity fill from the app-level theme (the Windows setting) rather than from the
    // RequestedTheme of its ancestors, so with Windows dark and Purge set to Light a warning bar showed dark brown.
    // Setting RequestedTheme on the bar itself makes it follow the window.
    private void PinInfoBars(DependencyObject node)
    {
        if (node is InfoBar bar) bar.RequestedTheme = Root.ActualTheme;
        var n = VisualTreeHelper.GetChildrenCount(node);
        for (var i = 0; i < n; i++) PinInfoBars(VisualTreeHelper.GetChild(node, i));
    }

    public nint Hwnd => WinRT.Interop.WindowNative.GetWindowHandle(this);

    public void SetProgramsCount(int count) => ProgramsCount.Text = count.ToString(System.Globalization.CultureInfo.CurrentCulture);

    public ElementTheme Theme => Root.RequestedTheme;

    public void ApplyTheme(ElementTheme theme)
    {
        Root.RequestedTheme = theme;
        if (ContentCard?.Child is { } current) PinInfoBars(current);
        AppWindow.TitleBar.PreferredTheme = theme switch
        {
            ElementTheme.Light => TitleBarTheme.Light,
            ElementTheme.Dark => TitleBarTheme.Dark,
            _ => TitleBarTheme.UseDefaultAppMode,
        };
    }


    private void SizeAndCenter(int width, int height)
    {
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var scale = GetDpiForWindow(hwnd) / 96.0;
        var size = new SizeInt32((int)(width * scale), (int)(height * scale));
        var area = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        size.Width = Math.Min(size.Width, area.Width);
        size.Height = Math.Min(size.Height, area.Height);
        AppWindow.MoveAndResize(new RectInt32(
            area.X + (area.Width - size.Width) / 2, area.Y + (area.Height - size.Height) / 2, size.Width, size.Height));
    }

    [LibraryImport("user32.dll")]
    private static partial uint GetDpiForWindow(nint hwnd);
}
