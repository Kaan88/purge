using System.Runtime.InteropServices;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Purge.App.Shell;
using Purge.App.Views;
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
        ExtendsContentIntoTitleBar = true;
        SetTitleBar(AppTitleBar);
        var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "Purge.ico");
        if (File.Exists(icon)) AppWindow.SetIcon(icon);
        SizeAndCenter(1360, 860);
        ApplyTheme(Program.Options.Theme);

        _rail =
        [
            (NavHome, SelHome, PillHome), (NavPrograms, SelPrograms, PillPrograms), (NavQueue, SelQueue, PillQueue),
            (NavLeftovers, SelLeftovers, PillLeftovers), (NavVault, SelVault, PillVault),
            (NavHistory, SelHistory, PillHistory), (NavFootprint, SelFootprint, PillFootprint),
            (NavStartup, SelStartup, PillStartup), (NavAssistant, SelAssistant, PillAssistant),
            (NavSettings, SelSettings, PillSettings),
        ];

        // S1 is the only view built for the first frame; its rows are set before Activate() when the list
        // reply is already in (§9.2 step 4).
        _programs = new ProgramsView();
        _views["programs"] = _programs;
        ContentCard.Child = _programs;
        if (Program.Startup.IsCompletedSuccessfully)
            OnStartup(Program.Startup.Result);
        else
            _ = LoadWhenReadyAsync();

        if (Program.Options.Page is { } page) Navigate(page);
        CompositionTarget.Rendering += OnFirstRendering;
        // No engine outlives the window: the client ends what it runs and closes its kill-on-close job.
        Closed += (_, _) => Program.Engine.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    private async Task LoadWhenReadyAsync() => OnStartup(await Program.Startup);

    private void OnStartup(StartupData data)
    {
        _programs.Load(data);
        // A sandbox dev engine says so in the title bar (and in Settings → About).
        if (data.Hello.BuildNote is { } note)
        {
            Title = $"Purge · {note}";
            AppTitleBar.Title = Title;
        }
        if (Shell.Alpha.On)
        {
            Title = "Purge (alpha)" + (data.Hello.BuildNote is { } n ? $" · {n}" : "");
            AppTitleBar.Title = Title;
        }
        if (data.Error is { } error) _programs.ShowEngineNotice(error);
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

        // Board 05: the search box is also the command palette; Ctrl+K and Ctrl+F both focus it.
        _palette = new CommandPalette(SearchBox, () => _programs);
        foreach (var key in new[] { Windows.System.VirtualKey.K, Windows.System.VirtualKey.F })
        {
            var accel = new KeyboardAccelerator { Key = key, Modifiers = Windows.System.VirtualKeyModifiers.Control };
            accel.Invoked += (_, a) => { a.Handled = true; _palette.Focus(); };
            Root.KeyboardAccelerators.Add(accel);
        }
        if (Program.Options.Query is { } query)
            DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () => _palette.Type(query));

        // Approximate "first presented frame": the next DWM composition after the first tick has been committed.
        // The precise number comes from Dwm-Core present events in WPR (§9.2 (a)).
        DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
        {
            _programs.OnFirstTick();
            Task.Run(() =>
            {
                LaunchMarkers.DwmFlush();
                LaunchMarkers.Mark("presented");
                LaunchMarkers.Flush();
                if (Program.Options.BenchExit)
                    DispatcherQueue.TryEnqueue(Close);
                else
                    DispatcherQueue.TryEnqueue(() => _programs.ShowLaunchTime());
            });
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

    private CommandPalette? _palette;

    public void Navigate(string key)
    {
        if (!_views.TryGetValue(key, out var view))
        {
            view = key switch
            {
                "queue" => new QueueView(),
                "leftovers" => new ReviewView(),
                "home" => new HomeView(),
                "vault" => new VaultView(),
                "history" => new HistoryView(),
                "footprint" => new FootprintView(),
                "assistant" => new AssistantView(),
                "startup" => PlaceholderView.Startup(),
                "settings" => new SettingsView(),
                _ => _programs,
            };
            // With the real engine, pages it does not feed yet say so above their sample content.
            if (Program.Engine.IsLive && key is "home" or "queue" or "history" or "footprint" or "assistant" or "startup")
                view = SampleBanner(view);
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

    private static Grid SampleBanner(UIElement view)
    {
        var grid = new Grid();
        grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        grid.RowDefinitions.Add(new RowDefinition());
        var banner = new TextBlock
        {
            Text = "Sample data: this page is not connected to the engine in this build.",
            Margin = new Thickness(28, 12, 28, 0),
            Opacity = 0.7,
        };
        grid.Children.Add(banner);
        Grid.SetRow((FrameworkElement)view, 1);
        grid.Children.Add(view);
        return grid;
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
