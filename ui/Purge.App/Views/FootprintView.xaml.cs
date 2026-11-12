using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>
/// Board 09 on sample data: sizes from <c>programs.sizes</c>, expected leftovers from <c>programs.forecast</c>
/// (proposed). Programs without a forecast show "Not known yet" and no band; nothing is guessed.
/// </summary>
public sealed partial class FootprintView : UserControl
{
    private const int Shown = 11;
    private List<FootprintItem> _items = [];
    private FootprintItem? _current;
    private bool _loaded;

    public FootprintView()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            if (_loaded) return;
            _loaded = true;
            await LoadAsync();
        };
    }

    private async Task LoadAsync()
    {
        var rows = MainWindow.Instance.Programs.All.Where(r => r.IsApp).ToList();
        IReadOnlyDictionary<string, long> sizes;
        IReadOnlyList<LeftoverForecast> forecasts;
        try
        {
            sizes = await Program.Engine.GetSizesAsync();
            forecasts = await Program.Engine.GetForecastsAsync(rows.Select(r => r.Entry.ProgramId).ToList());
        }
        catch (Exception e)
        {
            Summary.Text = "Couldn't read sizes: " + e.Message;
            return;
        }
        var byId = forecasts.ToDictionary(f => f.ProgramId);
        var all = rows
            .Select(r => new FootprintItem(r.Name, r.SubLine, r.TileBrush, r.Initial,
                sizes.TryGetValue(r.Entry.ProgramId, out var s) ? s : 0,
                byId.TryGetValue(r.Entry.ProgramId, out var f) ? f : null, r))
            .Where(i => i.Area > 0)
            .OrderByDescending(i => i.Area)
            .ToList();

        _items = all.Take(Shown).ToList();
        var rest = all.Skip(Shown).ToList();
        if (rest.Count > 0)
        {
            var known = rest.Where(r => r.Forecast?.EstimateBytes is not null).ToList();
            var sum = known.Sum(r => r.LeftoverBytes);
            var restForecast = sum > 0
                ? new LeftoverForecast("", ForecastVerdict.Some, sum, null, false, [])
                : null;
            _items.Add(new FootprintItem($"{rest.Count} smaller programs", "Grouped to keep the map readable",
                new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0x5A, 0x5A, 0x5A)), "…", rest.Sum(r => r.SizeBytes), restForecast, null, rest.Count));
        }

        var installed = all.Sum(i => i.SizeBytes);
        var left = all.Sum(i => i.LeftoverBytes);
        var knownCount = all.Count(i => i.Forecast is not null);
        Summary.Text = $"{ProgramRow.FormatSize(installed)} installed · about {ProgramRow.FormatSize(left)} expected to stay after removal " +
                       $"(known for {knownCount} of {all.Count} programs)";

        var max = _items.Max(i => i.Area);
        foreach (var i in _items) i.ListBar = max > 0 ? 200 * i.Area / max : 0;
        Relayout();
        Show(_items.FirstOrDefault(i => i.LeftoverBytes > 0) ?? _items.FirstOrDefault());
    }

    private void OnMapSizeChanged(object sender, SizeChangedEventArgs e) => Relayout();

    private void Relayout()
    {
        if (_items.Count == 0 || MapHost.ActualWidth <= 0) return;
        Treemap.Layout(_items, MapHost.ActualWidth, MapHost.ActualHeight);
        // Layout values are plain properties (x:Bind OneTime), so hand over a fresh list to re-render.
        Blocks.ItemsSource = _items.ToList();
    }

    private void OnBlock(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is FootprintItem item) Show(item);
    }

    private void OnRowSelected(object sender, SelectionChangedEventArgs e)
    {
        if (Rows.SelectedItem is FootprintItem item) Show(item);
    }

    // Map and List act as a pair: checking one unchecks the other; unchecking the active one is undone.
    private void OnToggleUnchecked(object sender, RoutedEventArgs e)
    {
        if (MapToggle.IsChecked != true && ListToggle.IsChecked != true && sender is ToggleButton t) t.IsChecked = true;
    }

    private void OnShowMap(object sender, RoutedEventArgs e)
    {
        if (ListToggle is null) return; // during InitializeComponent
        ListToggle.IsChecked = false;
        MapHost.Visibility = Visibility.Visible;
        if (Rows is not null) Rows.Visibility = Visibility.Collapsed;
    }

    private void OnShowList(object sender, RoutedEventArgs e)
    {
        MapToggle.IsChecked = false;
        if (Rows is null)
        {
            FindName(nameof(Rows));
            Rows.ItemsSource = _items;
        }
        Rows.Visibility = Visibility.Visible;
        MapHost.Visibility = Visibility.Collapsed;
        if (_current is not null) Rows.SelectedItem = _current;
    }

    private void Show(FootprintItem? item)
    {
        if (item is null) return;
        _current = item;
        DTile.Background = item.Tile;
        DInitial.Text = item.Initial;
        DName.Text = item.Name;
        DSub.Text = item.Sub;
        DSize.Text = item.SizeText;
        DLeft.Text = item.LeftoverText;
        DLines.ItemsSource = item.Forecast is { Lines.Count: > 0 } f
            ? f.Lines.Select(l => new ExpectLine(l.Kind, l.Text, l.Detail ?? "")).ToList()
            : new List<ExpectLine> { new(null, item.Count > 1 ? "Open the list to see each program" : "Purge has no record of what it leaves yet", "") };
        DNote.Text = item.Forecast?.HoldsUserData == true
            ? "Part of this is your data. Purge will not pre-select it."
            : item.Forecast is null ? "Expected leftovers are not known yet, so the map shows no band for it." : "";
        DNote.Visibility = DNote.Text.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        DUninstall.Visibility = item.Row is null ? Visibility.Collapsed : Visibility.Visible;
        DUninstall.Content = item.Row is null ? "" : $"Uninstall {item.Row.Name}";
    }

    /// <summary>Same path as the Programs page's Uninstall button.</summary>
    private void OnUninstall(object sender, RoutedEventArgs e)
    {
        if (_current?.Row is not { } row) return;
        MainWindow.Instance.Navigate("programs");
        MainWindow.Instance.Programs.Reveal(row);
        MainWindow.Instance.Programs.RunCommand("uninstall");
    }
}
