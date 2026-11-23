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
        PreMeasurePrograms();

        // The title bar goes last (M3 launch perf): the first ExtendsContentIntoTitleBar call waits until the
        // window's composition is ready (about 200 ms after start on the bench laptop, the same wait the bare
        // control pays in its first frame). Everything above runs before that wait ends instead of after it.
        // It is still before Activate(), so the window never shows the system caption.
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        LaunchMarkers.Mark("w_titlebar");
        _programs.WatchLiveRows();
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
        // Prepared may still be running on the engine reply thread; then Load builds the rows on this thread.
        _programs.Load(data, Program.Prepared is { IsCompletedSuccessfully: true } prepared ? prepared.Result : null);
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

    /// <summary>
    /// Shows the bar for a Windows prompt that did not lead to the broker over the top of the page (built on first
    /// use): "You cancelled the Windows prompt", or "Not started" when the user chose "Not now" at the explanation
    /// (<paramref name="declinedExplanation"/>, carried by the route's own launch result).
    /// </summary>
    public void ShowAdminPromptCancelled(bool declinedExplanation, Action? tryAgain = null)
    {
        if (_barHost is null && ContentCard.Parent is Grid grid)
        {
            _barHost = new StackPanel { VerticalAlignment = VerticalAlignment.Top, Margin = new Thickness(16, 12, 16, 0), Spacing = 8 };
            Grid.SetColumn(_barHost, 1);
            grid.Children.Add(_barHost);
        }
        if (_barHost is null) return;
        _barHost.Children.Clear();
        var bar = ElevationPrompts.CancelledBar(Root.ActualTheme, declinedExplanation, tryAgain);
        bar.Closed += (s, _) => _barHost.Children.Remove(s);
        _barHost.Children.Add(bar);
    }

    /// <summary>The S3 review page (built on first use); the Uninstall pipeline hands it the scan.</summary>
    public LeftoversView OpenReview()
    {
        Navigate("leftovers");
        return (LeftoversView)_views["leftovers"];
    }

    /// <summary>The S3 review page (built on first use) without showing it: a held scan handed over off screen.</summary>
    public LeftoversView ReviewPage => (LeftoversView)ViewFor("leftovers");

    /// <summary>The program whose scan the Uninstall page holds for the Leftovers page; null when none waits.</summary>
    public string? HeldScanProgram => _views.TryGetValue("queue", out var view) && view is UninstallView uninstall
        ? uninstall.HeldProgram
        : null;

    /// <summary>The Uninstall page started or stopped holding a scan: the Leftovers page's line follows it. UI thread.</summary>
    public void OnHeldScanChanged()
    {
        if (_views.TryGetValue("leftovers", out var view) && view is LeftoversView leftovers) leftovers.OnHeldScanChanged();
    }

    /// <summary>The Leftovers page's "Show the scan": the held scan replaces what that page shows.</summary>
    public void ShowHeldScan()
    {
        if (_views.TryGetValue("queue", out var view) && view is UninstallView uninstall) uninstall.ShowHeld();
    }

    /// <summary>True while the Leftovers page (if built) applies a change over its broker link.</summary>
    public bool LeftoversChanging => _views.TryGetValue("leftovers", out var view) && view is LeftoversView { IsChanging: true };

    /// <summary>True while the Uninstall pipeline (if built) runs a step; the removed-program check waits meanwhile.</summary>
    public bool UninstallBusy => _views.TryGetValue("queue", out var view) && view is UninstallView { IsBusy: true };

    /// <summary>True while a removed program's leftovers check runs; the Uninstall page's actions wait meanwhile.</summary>
    public bool CheckRunning => _programs.CheckRunning;

    /// <summary>
    /// The Leftovers page started or finished applying a change: the removed rows' buttons follow it, and a scan the
    /// Uninstall page holds for that page is handed over once the change is done. UI thread.
    /// </summary>
    public void OnLeftoversChangingChanged()
    {
        _programs.OnBrokerUsersChanged();
        if (_views.TryGetValue("queue", out var view) && view is UninstallView uninstall) uninstall.OnLeftoversChangingChanged();
    }

    /// <summary>A removed program's leftovers check started or ended: the Uninstall page's actions follow it. UI thread.</summary>
    public void OnCheckRunningChanged()
    {
        if (_views.TryGetValue("queue", out var view) && view is UninstallView uninstall) uninstall.OnCheckRunningChanged();
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
        _programs.RecordRowsAtTick();

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

    /// <summary>The view of a rail key, built on first use (not shown).</summary>
    private UIElement ViewFor(string key)
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
        return view;
    }

    public void Navigate(string key)
    {
        var leftLeftovers = CurrentPage == "leftovers" && key != "leftovers";
        var view = ViewFor(key);
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
        // A scan the Uninstall page held while the Leftovers page showed a change's outcome goes there now.
        if (leftLeftovers && _views.TryGetValue("queue", out var queue) && queue is UninstallView uninstall)
            uninstall.OnLeftoversLeft();
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
        // Below 760 x 520 the Programs page cannot lay out its tabs, tools and a readable Name column.
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.PreferredMinimumWidth = (int)(760 * scale);
            presenter.PreferredMinimumHeight = (int)(520 * scale);
        }
        var size = new SizeInt32((int)(width * scale), (int)(height * scale));
        var area = DisplayArea.GetFromWindowId(AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        size.Width = Math.Min(size.Width, area.Width);
        size.Height = Math.Min(size.Height, area.Height);
        AppWindow.MoveAndResize(new RectInt32(
            area.X + (area.Width - size.Width) / 2, area.Y + (area.Height - size.Height) / 2, size.Width, size.Height));
    }

    /// <summary>Width of the rail column and height of the title bar row in MainWindow.xaml (plus the card's 1 px border).</summary>
    private const double RailWidth = 232, TitleBarHeight = 48, CardBorder = 1;

    /// <summary>
    /// Lays out the Programs page once at the size it will get, while the title bar call below still has to wait
    /// for composition (M3 launch perf): templates are applied now instead of after Activate(). The list realizes
    /// only one row container here (a diagnostic build counted 1 at the end of the constructor); the live layout
    /// after Activate() realizes the first screenful and measures the page again, so a size that is slightly off
    /// only means it does more of that work itself.
    /// </summary>
    private void PreMeasurePrograms()
    {
        if (ContentCard.Child != _programs) return;
        var hwnd = WinRT.Interop.WindowNative.GetWindowHandle(this);
        var dpi = GetDpiForWindow(hwnd);
        if (dpi == 0 || !GetClientRect(hwnd, out var client)) return;
        var scale = dpi / 96.0;
        // The client area does not include the system caption yet; the extended title bar takes it over.
        var caption = GetSystemMetricsForDpi(SmCyCaption, dpi) + GetSystemMetricsForDpi(SmCySizeFrame, dpi)
                      + GetSystemMetricsForDpi(SmCxPaddedBorder, dpi);
        var width = (client.Right - client.Left) / scale - RailWidth - CardBorder;
        var height = (client.Bottom - client.Top + caption) / scale - TitleBarHeight - CardBorder;
        if (width <= 0 || height <= 0) return;
        _programs.Measure(new Windows.Foundation.Size(width, height));
        _programs.Arrange(new Windows.Foundation.Rect(0, 0, width, height));
    }

    private const int SmCyCaption = 4, SmCySizeFrame = 33, SmCxPaddedBorder = 92;

    [StructLayout(LayoutKind.Sequential)]
    private struct Rect32
    {
        public int Left, Top, Right, Bottom;
    }

    [LibraryImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetClientRect(nint hwnd, out Rect32 rect);

    [LibraryImport("user32.dll")]
    private static partial int GetSystemMetricsForDpi(int index, uint dpi);

    [LibraryImport("user32.dll")]
    private static partial uint GetDpiForWindow(nint hwnd);
}
