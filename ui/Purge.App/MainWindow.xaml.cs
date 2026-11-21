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
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        LaunchMarkers.Mark("w_titlebar");
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
        if (Program.Startup.IsCompletedSuccessfully)
            OnStartup(Program.Startup.Result);
        else
            _ = LoadWhenReadyAsync();

        if (Program.Options.Page is { } page) Navigate(page);
        LaunchMarkers.Mark("rows_set");
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
        if (data.Error is { } error) _programs.ShowEngineNotice(error);
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

    /// <summary>The S3 review page (built on first use), for the scan started from S1.</summary>
    public ReviewView OpenReview()
    {
        Navigate("leftovers");
        return (ReviewView)_views["leftovers"];
    }

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
                LaunchMarkers.Flush();
            }
            _programs.OnFirstTick();
            if (Program.Options.BenchExit)
                // Close runs the Closed handler (engine disposal); Exit ends Application.Start, which
                // closing the last window does not do on its own for an unpackaged app.
                DispatcherQueue.TryEnqueue(() => { Close(); Application.Current.Exit(); });
            else
                DispatcherQueue.TryEnqueue(() => _programs.ShowLaunchTime());
        });
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
                "queue" => new QueueView(),
                "leftovers" => new ReviewView(),
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
