using System.Diagnostics;
using System.Globalization;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>A line of "What Purge expects" in the details card.</summary>
public sealed partial class ExpectLine(ForecastLineKind? kind, string text, string detail)
{
    public string Text { get; } = text;
    public string Detail { get; } = detail;
    public Visibility OkVisibility => kind == ForecastLineKind.Removed ? Visibility.Visible : Visibility.Collapsed;
    public Visibility WarnVisibility => kind == ForecastLineKind.Stays ? Visibility.Visible : Visibility.Collapsed;
    public Visibility UserVisibility => kind == ForecastLineKind.UserData ? Visibility.Visible : Visibility.Collapsed;
    public Visibility UnknownVisibility => kind is null ? Visibility.Visible : Visibility.Collapsed;
}

public sealed partial class ProgramsView : UserControl
{
    private const int ForecastBatch = 8;

    private List<ProgramRow> _all = [];
    private IReadOnlyDictionary<string, long> _sizes = new Dictionary<string, long>();
    private readonly Dictionary<string, LeftoverForecast?> _forecasts = new(StringComparer.Ordinal);
    private InventoryDoc? _doc;
    private ProgramTab _tab = ProgramTab.Apps;
    private string _query = "";
    private string _sortKey = "name";
    private bool _sortDescending;
    private bool _firstTickDone;
    private bool _refreshing;
    private bool _onlyLeftovers, _onlyPerUser, _only32;
    private ProgramRow? _current;
    private readonly (Button Button, Border Selection, TextBlock Label, TextBlock Count, ProgramTab Tab)[] _tabs;

    public ProgramsView()
    {
        InitializeComponent();
        _tabs =
        [
            (TabApps, TabAppsSel, TabAppsLabel, TabAppsCount, ProgramTab.Apps),
            (TabComponents, TabComponentsSel, TabComponentsLabel, TabComponentsCount, ProgramTab.Components),
            (TabUnnamed, TabUnnamedSel, TabUnnamedLabel, TabUnnamedCount, ProgramTab.Unnamed),
            (TabStore, TabStoreSel, TabStoreLabel, TabStoreCount, ProgramTab.Store),
            (TabRecent, TabRecentSel, TabRecentLabel, TabRecentCount, ProgramTab.Recent),
        ];
        UpdateSortHeaders();
    }

    /// <summary>All rows, for the command box in the title bar.</summary>
    public IReadOnlyList<ProgramRow> All => _all;

    /// <summary>Takes the <c>programs.list</c> reply. Called before Activate() when it has already arrived.</summary>
    public void Load(StartupData data)
    {
        _doc = data.Inventory;
        Rebuild();
        _ = LoadSizesAsync();
    }

    private async Task LoadSizesAsync()
    {
        _sizes = await Program.Engine.GetSizesAsync();
        Rebuild();
    }

    private void Rebuild()
    {
        if (_doc is null) return;
        var today = DateTime.Today;
        var currentId = _current?.Entry.ProgramId;
        _all = _doc.Entries.Select(e => new ProgramRow(e, _sizes.TryGetValue(e.ProgramId, out var s) ? s : null, today)).ToList();
        var max = Math.Max(1, _all.Max(r => r.SizeBytes ?? 0));
        foreach (var r in _all)
        {
            r.BarWidth = r.SizeBytes is { } b and > 0 ? Math.Max(2, 96.0 * b / max) : 0;
            if (_forecasts.TryGetValue(r.Entry.ProgramId, out var f)) r.Forecast = f;
            r.Extras = _firstTickDone;
        }
        _current = currentId is null ? null : _all.FirstOrDefault(r => r.Entry.ProgramId == currentId);
        if (_firstTickDone) UpdateTabCounts();
        UpdateSummary();
        MainWindow.Instance.SetProgramsCount(_all.Count);
        Refresh();
    }

    /// <summary>Work deferred to after the first Rendering tick (§9.2 step 3).</summary>
    public void OnFirstTick()
    {
        _firstTickDone = true;
        UpdateTabCounts();
        FindName(nameof(Commands));
        PlainCommands.Visibility = Visibility.Collapsed;
        // Sample: in M3 this group comes from inventory.changes (programs removed outside Purge).
        FindName(nameof(Attention));
        foreach (var r in _all) r.Extras = true;
        UpdateSummary();
        _ = LoadForecastsAsync();
    }

    /// <summary>
    /// Asks for expected leftovers in small batches, in list order, so the visible rows fill first. Until a
    /// program's answer is in, and when the engine has none, the row says "Not known yet".
    /// </summary>
    private async Task LoadForecastsAsync()
    {
        var order = (ProgramList.ItemsSource as List<ProgramRow> ?? []).Concat(_all).Select(r => r.Entry.ProgramId).Distinct().ToList();
        for (var i = 0; i < order.Count; i += ForecastBatch)
        {
            var batch = order.Skip(i).Take(ForecastBatch).ToList();
            IReadOnlyList<LeftoverForecast> got;
            try { got = await Program.Engine.GetForecastsAsync(batch); }
            catch (Exception) { return; } // Leave the rest as "Not known yet".
            foreach (var id in batch) _forecasts[id] = null;
            foreach (var f in got) _forecasts[f.ProgramId] = f;
            foreach (var r in _all)
                if (batch.Contains(r.Entry.ProgramId)) r.Forecast = _forecasts[r.Entry.ProgramId];
            UpdateSummary();
            if (_current is not null && batch.Contains(_current.Entry.ProgramId)) ShowDetails(_current);
        }
    }

    public void ShowLaunchTime() => UpdateStatus();

    private void UpdateSummary()
    {
        var total = _all.Sum(r => r.SizeBytes ?? 0);
        var text = $"{_all.Count} entries · {ProgramRow.FormatSize(total)}";
        var apps = _all.Where(r => r.IsApp).ToList();
        if (_forecasts.Count >= _all.Count)
            text += $" · {apps.Count(r => r.Verdict is ForecastVerdict.Some or ForecastVerdict.Large)} would leave leftovers";
        else if (_firstTickDone)
            text += " · checking expected leftovers…";
        Summary.Text = text;
        if (_firstTickDone)
            AllAppsLabel.Text = $"ALL {TabLabel(_tab).ToUpper(CultureInfo.CurrentCulture)} · {(ProgramList.ItemsSource as List<ProgramRow>)?.Count ?? 0}";
        UpdateStatus();
    }

    private void UpdateStatus()
    {
        if (!_firstTickDone) return;
        var shown = ProgramList.ItemsSource as List<ProgramRow> ?? [];
        StatusLeft.Text = $"{shown.Count} {TabLabel(_tab).ToLower(CultureInfo.CurrentCulture)} · {ProgramRow.FormatSize(shown.Sum(r => r.SizeBytes ?? 0))}";
        var right = "Sample data · engine not connected";
        if (LaunchMarkers.Get("list_reply") is { } reply) right += $" · list in {reply.ToString("F0", CultureInfo.CurrentCulture)} ms";
        if (LaunchMarkers.Get("presented") is { } ms) right += $" · on screen in {ms.ToString("F0", CultureInfo.CurrentCulture)} ms";
        StatusRight.Text = right;
    }

    private static string TabLabel(ProgramTab tab) => tab switch
    {
        ProgramTab.Apps => "Apps",
        ProgramTab.Components => "Components",
        ProgramTab.Unnamed => "Unnamed",
        ProgramTab.Store => "Store apps",
        _ => "Recent",
    };

    public void SetSearch(string query)
    {
        _query = query.Trim();
        Refresh();
    }

    /// <summary>Selects one program (from the command box) and shows it.</summary>
    public void Reveal(ProgramRow row)
    {
        if (!row.InTab(_tab)) SelectTab(row.IsApp ? ProgramTab.Apps : row.IsComponent ? ProgramTab.Components : ProgramTab.Unnamed);
        _query = "";
        Refresh();
        ProgramList.SelectedItems.Clear();
        ProgramList.SelectedItem = row;
        ProgramList.ScrollIntoView(row);
        _current = row;
        ShowDetails(row);
    }

    private void Refresh()
    {
        IEnumerable<ProgramRow> rows = _all.Where(r => r.InTab(_tab) && r.Matches(_query)
                                                       && (!_onlyLeftovers || r.Verdict is ForecastVerdict.Some or ForecastVerdict.Large)
                                                       && (!_onlyPerUser || r.Entry.Scope == InstallScope.User)
                                                       && (!_only32 || r.Entry.View == RegistryView.K32));
        rows = _sortKey switch
        {
            "publisher" => Order(rows, r => r.Publisher),
            "size" => Order(rows, r => r.SizeBytes ?? -1),
            "junk" => Order(rows, r => r.JunkRank),
            "date" => Order(rows, r => r.Installed ?? DateTime.MinValue),
            _ => Order(rows, r => r.Name),
        };
        var list = rows.ToList();

        _refreshing = true;
        ProgramList.ItemsSource = list;
        var keep = _current is null ? null : list.FirstOrDefault(r => r.Entry.ProgramId == _current.Entry.ProgramId);
        if (keep is null && list.Count > 0) keep = list[0];
        if (keep is not null) ProgramList.SelectedItem = keep;
        _refreshing = false;

        _current = keep;
        ShowDetails(keep);
        UpdateSelectedCount();
        if (_firstTickDone) UpdateSummary();
    }

    private IEnumerable<ProgramRow> Order<TKey>(IEnumerable<ProgramRow> rows, Func<ProgramRow, TKey> key)
    {
        // Child rows (updates, Burn children) stay directly under their parent.
        var byKey = _all.ToDictionary(r => KeyName(r.Entry.KeyPath), r => r);
        var all = rows.ToList();
        var parents = all.Where(r => !r.IsChild || !byKey.ContainsKey(r.Entry.Flags.ParentKey!));
        var ordered = _sortDescending ? parents.OrderByDescending(key) : parents.OrderBy(key);
        var children = all.Where(r => r.IsChild && byKey.ContainsKey(r.Entry.Flags.ParentKey!)).ToList();
        foreach (var p in ordered)
        {
            yield return p;
            foreach (var c in children)
                if (c.Entry.Flags.ParentKey == KeyName(p.Entry.KeyPath)) yield return c;
        }
    }

    private static string KeyName(string keyPath) => keyPath[(keyPath.LastIndexOf('\\') + 1)..];

    private void UpdateTabCounts()
    {
        TabAppsCount.Text = _all.Count(r => r.IsApp).ToString(CultureInfo.CurrentCulture);
        TabComponentsCount.Text = _all.Count(r => r.IsComponent).ToString(CultureInfo.CurrentCulture);
        TabUnnamedCount.Text = _all.Count(r => r.IsUnnamed).ToString(CultureInfo.CurrentCulture);
        TabStoreCount.Text = "…";
        TabRecentCount.Text = _all.Count(r => r.IsRecent).ToString(CultureInfo.CurrentCulture);
    }

    private void OnTab(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string tag } || !Enum.TryParse<ProgramTab>(tag, out var tab)) return;
        SelectTab(tab);
        Refresh();
    }

    private void SelectTab(ProgramTab tab)
    {
        _tab = tab;
        foreach (var t in _tabs)
        {
            var on = t.Tab == tab;
            t.Selection.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
            t.Label.FontWeight = on ? FontWeights.SemiBold : FontWeights.Normal;
        }
    }

    private void OnSort(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string key }) return;
        if (_sortKey == key) _sortDescending = !_sortDescending;
        else { _sortKey = key; _sortDescending = key is "size" or "date" or "junk"; }
        UpdateSortHeaders();
        Refresh();
    }

    private void OnSortMenu(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string key }) return;
        _sortKey = key;
        _sortDescending = key is "size" or "date" or "junk";
        UpdateSortHeaders();
        Refresh();
    }

    private void UpdateSortHeaders()
    {
        var arrow = _sortDescending ? " ↓" : " ↑";
        SortName.Content = "Name" + (_sortKey == "name" ? arrow : "");
        SortSize.Content = "Size" + (_sortKey == "size" ? arrow : "");
        SortJunk.Content = "Expected leftovers" + (_sortKey == "junk" ? arrow : "");
        SortDate.Content = "Installed" + (_sortKey == "date" ? arrow : "");
        SortButton.Content = "Sort: " + _sortKey switch
        {
            "publisher" => "Publisher",
            "size" => "Size",
            "junk" => "Expected leftovers",
            "date" => "Install date",
            _ => "Name",
        };
    }

    private void OnFilter(object sender, RoutedEventArgs e)
    {
        // Built on first use (§9.2 step 3).
        if (FilterButton.Flyout is null)
        {
            var menu = new MenuFlyout { Placement = Microsoft.UI.Xaml.Controls.Primitives.FlyoutPlacementMode.BottomEdgeAlignedRight };
            menu.Items.Add(FilterItem("Would leave leftovers", () => _onlyLeftovers, v => _onlyLeftovers = v));
            menu.Items.Add(FilterItem("Installed for this user only", () => _onlyPerUser, v => _onlyPerUser = v));
            menu.Items.Add(FilterItem("32-bit only", () => _only32, v => _only32 = v));
            FilterButton.Flyout = menu;
        }
        FilterButton.Flyout.ShowAt(FilterButton);
    }

    private ToggleMenuFlyoutItem FilterItem(string text, Func<bool> get, Action<bool> set)
    {
        var item = new ToggleMenuFlyoutItem { Text = text, IsChecked = get() };
        item.Click += (_, _) =>
        {
            set(item.IsChecked);
            var n = (_onlyLeftovers ? 1 : 0) + (_onlyPerUser ? 1 : 0) + (_only32 ? 1 : 0);
            FilterText.Text = n == 0 ? "Filter" : $"Filter ({n})";
            Refresh();
        };
        return item;
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshing) return;
        // The details card follows the row most recently ticked; unticking it falls back to another ticked row.
        if (e.AddedItems.Count > 0 && e.AddedItems[^1] is ProgramRow added)
            _current = added;
        else if (_current is not null && e.RemovedItems.Contains(_current))
            _current = ProgramList.SelectedItems.Count > 0 ? ProgramList.SelectedItems[^1] as ProgramRow : null;
        ShowDetails(_current);
        UpdateSelectedCount();
    }

    private void UpdateSelectedCount()
    {
        var n = ProgramList.SelectedItems.Count;
        SelectedCount.Text = n == 0 ? "" : $"{n} selected";
    }

    private void ShowDetails(ProgramRow? row)
    {
        if (row is null) { Details.Visibility = Visibility.Collapsed; return; }
        Details.Visibility = Visibility.Visible;
        var e = row.Entry;
        DTile.Background = row.TileBrush;
        DInitial.Text = row.Initial;
        DName.Text = row.Name;
        DSub.Text = Join(" · ", row.Publisher, row.Version, row.KindChip);
        DUninstaller.Text = e.UninstallString is null
            ? "None registered"
            : row.KindText + (e.QuietUninstallString is not null || e.InstallerKind == InstallerKind.Msi ? " · quiet mode available" : "");
        DLocation.Content = e.InstallLocation ?? "Not recorded";
        DLocation.IsEnabled = e.InstallLocation is not null;
        DInstalled.Text = Join(" · ", row.InstalledText, "for " + row.ScopeText);
        DSize.Text = row.SizeText.Length > 0 ? row.SizeText : "Not measured";
        DPlatform.Text = row.BitsText;

        DExpects.ItemsSource = row.Forecast is { } f
            ? f.Lines.Select(l => new ExpectLine(l.Kind, l.Text, l.Detail ?? "")).ToList()
            : new List<ExpectLine>
            {
                new(null, _forecasts.ContainsKey(e.ProgramId)
                    ? "Not known yet. Purge has no record of what this installer put on the PC, so it will scan after the uninstaller ran."
                    : "Checking what this program is expected to leave…", ""),
            };

        var owns = RelatedTo(row);
        DOwns.Text = string.Join(", ", owns);
        DOwnsLabel.Visibility = DOwns.Visibility = owns.Count > 0 ? Visibility.Visible : Visibility.Collapsed;

        DUninstall.Text = e.UninstallString ?? "None";
        DQuiet.Text = e.QuietUninstallString ?? "None";
        var code = e.ProductCode ?? e.UpgradeCode;
        DProductLabel.Visibility = DProduct.Visibility = code is null ? Visibility.Collapsed : Visibility.Visible;
        DProduct.Text = code ?? "";
        DKey.Text = e.KeyPath;
    }

    /// <summary>
    /// Entries that belong with this one: its child keys, and same-publisher entries named after it
    /// ("Mozilla Firefox" → "Mozilla Maintenance Service"). A UI hint only; ownership is the engine's job.
    /// </summary>
    private List<string> RelatedTo(ProgramRow row)
    {
        var key = KeyName(row.Entry.KeyPath);
        var firstWord = row.Name.Split(' ', 2)[0];
        return _all
            .Where(r => r != row && r.Entry.Flags.HasDisplayName
                        && (r.Entry.Flags.ParentKey == key
                            || (r.Publisher.Length > 0 && r.Publisher == row.Publisher && !r.IsChild
                                && firstWord.Length >= 4 && r.Name.StartsWith(firstWord, StringComparison.OrdinalIgnoreCase))))
            .Select(r => r.Name)
            .Take(3)
            .ToList();
    }

    private static string Join(string sep, params string[] parts) =>
        string.Join(sep, parts.Where(p => !string.IsNullOrEmpty(p)));

    private void OnCommand(object sender, RoutedEventArgs e) => RunCommand((sender as FrameworkElement)?.Tag as string ?? "");

    /// <summary>
    /// Runs a program command. Buttons and the command box both come here, so a typed command takes exactly the
    /// steps its button takes.
    /// </summary>
    public void RunCommand(string tag)
    {
        if (tag == "more-pending")
        {
            // Clicked before the first tick finished: load the CommandBar now and open its overflow.
            FindName(nameof(Commands));
            PlainCommands.Visibility = Visibility.Collapsed;
            Commands.IsOpen = true;
            return;
        }
        if (tag == "open-folder" && _current?.Entry.InstallLocation is { } dir && Directory.Exists(dir))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = false });
            return;
        }
        var n = ProgramList.SelectedItems.Count;
        var what = n > 1 ? $"{n} programs" : _current?.Name ?? "this program";
        ShowNotice($"Not connected yet: this preview runs on sample data, so nothing happens to {what}. The engine connection arrives in M3.");
    }

    private void OnReviewRemoved(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("leftovers");

    private void ShowNotice(string message)
    {
        foreach (var child in InfoBarHost.Children.OfType<InfoBar>().Where(b => b.Tag is "notice").ToList())
            InfoBarHost.Children.Remove(child);
        var bar = new InfoBar
        {
            Severity = InfoBarSeverity.Warning, Message = message, IsOpen = true, IsClosable = true, Tag = "notice",
        };
        // Pin to the window theme: code-made InfoBars otherwise take the warning/info fill from the app theme
        // (Windows setting), not from Settings → Appearance.
        bar.RequestedTheme = MainWindow.Instance.ActualTheme;
        bar.Closed += (s, _) => InfoBarHost.Children.Remove(s);
        InfoBarHost.Children.Add(bar);
    }
}
