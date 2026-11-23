using System.Diagnostics;
using System.Globalization;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Purge.Client;
using Purge.Client.Model;
using Purge.Client.Pipeline;

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

/// <summary>A program the stored list had and the registry no longer has ("removed outside Purge", 7a delta 5).</summary>
public sealed partial class RemovedRow(Purge.Client.Rpc.ProgramRef program, bool canCheck, string checkHint)
{
    public string ProgramId { get; } = program.ProgramId;
    public string Name { get; } = program.Name;
    public string Initial { get; } = program.Name.Length > 0 && char.IsLetterOrDigit(program.Name[0]) ? char.ToUpperInvariant(program.Name[0]).ToString() : "?";

    /// <summary>No stored fingerprint exists for it, so no leftover count is claimed.</summary>
    public string Detail => "Not installed any more. Removed outside Purge, so there is no record of what it left.";

    public bool CanCheck { get; } = canCheck;
    public string CheckHint { get; } = checkHint;
}

public sealed partial class ProgramsView : UserControl
{
    private const int ForecastBatch = 8;
    private const int SizeChunk = 16;
    private const int MaxRemovedShown = 5;

    private List<ProgramRow> _all = [];
    private readonly Dictionary<string, ProgramRow> _byId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, long> _sizes = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Microsoft.UI.Xaml.Media.ImageSource> _icons = new(StringComparer.Ordinal);
    private readonly Dictionary<string, LeftoverForecast?> _forecasts = new(StringComparer.Ordinal);
    private InventoryDoc? _doc;
    private StartupResult? _startup;
    private ProgramTab _tab = ProgramTab.Apps;
    private string _query = "";
    private string _sortKey = "name";
    private bool _sortDescending;
    private bool _firstTickDone;
    private bool _refreshing;
    private bool _onlyLeftovers, _onlyPerUser, _only32;
    private bool _changesShown;
    private bool _patchesHooked;
    private long _maxSize = 1;
    private int _sizesDone;
    private bool _sizing;
    private CancellationTokenSource? _enrich;
    private IconAtlas? _atlas;
    private ProgramRow? _current;
    private readonly (Button Button, Border Selection, TextBlock Label, TextBlock Count, ProgramTab Tab)[] _tabs;

    public ProgramsView()
    {
        LaunchMarkers.Mark("programs_enter");
        InitializeComponent();
        LaunchMarkers.Mark("programs_xaml");
        _tabs =
        [
            (TabApps, TabAppsSel, TabAppsLabel, TabAppsCount, ProgramTab.Apps),
            (TabComponents, TabComponentsSel, TabComponentsLabel, TabComponentsCount, ProgramTab.Components),
            (TabUnnamed, TabUnnamedSel, TabUnnamedLabel, TabUnnamedCount, ProgramTab.Unnamed),
            (TabRecent, TabRecentSel, TabRecentLabel, TabRecentCount, ProgramTab.Recent),
        ];
        UpdateSortHeaders();
        UpdateCommandState();
        ProgramList.ContainerContentChanging += (_, _) =>
        {
            if (_firstRowSeen) return;
            _firstRowSeen = true;
            LaunchMarkers.Mark("first_row");
            // Rows that come after the first presented frame (a real engine's list): names are visible in the next one.
            if (_presented) MainWindow.Instance.MarkAfterNextFrame("names_visible");
        };
    }

    private bool _firstRowSeen;
    private bool _presented;

    /// <summary>Row height of the list (M3 design 9.3), for the size of the first screenful.</summary>
    private const double RowHeight = 40;

    /// <summary>Bench only: the ids of the first screenful whose icons are not settled yet (<c>icons_visible</c>).</summary>
    private HashSet<string>? _iconsPending;
    private bool _iconsMarked;

    /// <summary>The icon load in progress (completed when none is); the bench lets it save the atlas before exiting.</summary>
    public Task IconsDone { get; private set; } = Task.CompletedTask;

    /// <summary>
    /// Bench only, right after the <c>presented</c> marker: rows realized before it were in that frame, so
    /// <c>names_visible</c> is <c>presented</c>; otherwise it is marked after the frame that follows the first row.
    /// </summary>
    public void OnPresented()
    {
        _presented = true;
        if (!_firstRowSeen || LaunchMarkers.Get("presented") is not { } presented) return;
        LaunchMarkers.Record("names_visible", presented);
        MainWindow.Instance.BenchReached("names_visible");
    }

    /// <summary>The icon atlas file: the user's, or a bench run's own (<c>PURGE_BENCH_ICON_ATLAS</c>, bench only).</summary>
    private static string? BenchAtlasFile() =>
        LaunchMarkers.Enabled && Environment.GetEnvironmentVariable("PURGE_BENCH_ICON_ATLAS") is { Length: > 0 } file ? file : null;

    /// <summary>All rows, for the command box in the title bar.</summary>
    public IReadOnlyList<ProgramRow> All => _all;

    /// <summary>Takes the <c>programs.list</c> reply. Called before Activate() when it has already arrived.</summary>
    public void Load(StartupResult data)
    {
        _doc = data.Inventory;
        _startup = data;
        if (!_patchesHooked)
        {
            _patchesHooked = true;
            data.Engine.ProgramsPatched += OnLatePatches;
        }
        UpdateCommandState();
        Rebuild();
        // The list can arrive after the first tick; then what the tick would have started starts here.
        if (_firstTickDone) StartAfterFirstFrame();
    }

    private void Rebuild()
    {
        if (_doc is null) return;
        var today = DateTime.Today;
        var currentId = _current?.Entry.ProgramId;
        _all = _doc.Entries.Select(e => new ProgramRow(e, _sizes.TryGetValue(e.ProgramId, out var s) ? s : null, today)).ToList();
        _byId.Clear();
        foreach (var r in _all)
        {
            _byId[r.Entry.ProgramId] = r;
            if (_icons.TryGetValue(r.Entry.ProgramId, out var image)) r.SetIcon(image);
        }
        UpdateBars();
        foreach (var r in _all)
        {
            if (_forecasts.TryGetValue(r.Entry.ProgramId, out var f)) r.Forecast = f;
            r.Extras = _firstTickDone;
        }
        _current = currentId is not null && _byId.TryGetValue(currentId, out var again) ? again : null;
        if (_firstTickDone) UpdateTabCounts();
        UpdateSummary();
        MainWindow.Instance.SetProgramsCount(_all.Count);
        Refresh();
    }

    private void UpdateBars()
    {
        _maxSize = Math.Max(1, _all.Max(r => r.SizeBytes ?? 0));
        foreach (var r in _all)
            r.BarWidth = r.SizeBytes is { } b and > 0 ? Math.Max(2, 96.0 * b / _maxSize) : 0;
    }

    /// <summary>Work deferred to after the first Rendering tick (A9.2 step 3).</summary>
    public void OnFirstTick()
    {
        _firstTickDone = true;
        // The ListView default container transitions, left out of the first frame (see the XAML).
        ProgramList.ItemContainerTransitions =
        [
            new AddDeleteThemeTransition(),
            new ContentThemeTransition(),
            new ReorderThemeTransition(),
            new EntranceThemeTransition { IsStaggeringEnabled = false },
        ];
        UpdateTabCounts();
        FindName(nameof(Commands));
        PlainCommands.Visibility = Visibility.Collapsed;
        foreach (var r in _all) r.Extras = true;
        // The details pane is created here, not for the first frame (A9.2 step 3).
        ShowDetails(_current);
        UpdateSummary();
        if (_doc is not null) StartAfterFirstFrame();
    }

    private void StartAfterFirstFrame()
    {
        _ = ShowRemovedAsync(_startup?.Changes);
        StartEnrichment();
        _ = LoadForecastsAsync();
    }

    /// <summary>
    /// Fills the rows' icons and sizes, viewport first: what the list shows now comes first, then the rest in list
    /// order. The engine answers one request at a time, so both go in small chunks and a details request waits for
    /// at most one of them.
    /// </summary>
    private void StartEnrichment()
    {
        _enrich?.Cancel();
        var cts = _enrich = new CancellationTokenSource();
        var engine = Program.Engine;
        var shown = ProgramList.ItemsSource as List<ProgramRow> ?? [];
        var order = shown.Concat(_all).Select(r => r.Entry).DistinctBy(e => e.ProgramId).ToList();
        _sizesDone = 0;
        _sizing = true;
        // Bench only: the first screenful (rows the list can show at once) waits for its icons. Sample data has none.
        if (LaunchMarkers.Enabled && engine.IsLive && _iconsPending is null && shown.Count > 0)
        {
            var rows = ProgramList.ActualHeight > 0 ? (int)Math.Ceiling(ProgramList.ActualHeight / RowHeight) : 20;
            _iconsPending = shown.Take(rows).Select(r => r.Entry.ProgramId).ToHashSet(StringComparer.Ordinal);
        }
        IconsDone = RunIconsAsync(engine, order, cts.Token);
        _ = RunSizesAsync(engine, order.Select(e => e.ProgramId).ToList(), cts.Token);
    }

    /// <summary>Bench only: icons of these ids are applied or known to be missing; the last of the first screenful marks it.</summary>
    private void OnIconsAnswered(IReadOnlyList<string> ids)
    {
        if (_iconsPending is null || _iconsMarked) return;
        _iconsPending.ExceptWith(ids);
        if (_iconsPending.Count > 0) return;
        _iconsMarked = true;
        MainWindow.Instance.MarkAfterNextFrame("icons_visible");
    }

    private async Task RunIconsAsync(IEngineClient engine, List<InventoryEntry> order, CancellationToken ct)
    {
        var request = order.Select(e => (e.ProgramId, IconLoader.Stamp(e.Version, e.InstallTimeEvidence is { Count: > 0 } ev ? ev.Min(x => x.Time) : null))).ToList();
        try
        {
            await Task.Run(async () =>
            {
                // Sample data keeps no cache: its icons are made up and must not reach the user's atlas file.
                var atlas = engine.IsLive ? _atlas ??= new IconAtlas(BenchAtlasFile()) : null;
                Action<IReadOnlyList<string>>? answered = _iconsPending is null ? null : ids =>
                    DispatcherQueue.TryEnqueue(() => { if (!ct.IsCancellationRequested) OnIconsAnswered(ids); });
                await IconLoader.LoadAsync(engine, atlas, request, (id, icon) =>
                    DispatcherQueue.TryEnqueue(() => { if (!ct.IsCancellationRequested) ApplyIcon(id, icon); }), ct, answered).ConfigureAwait(false);
            }, ct);
        }
        catch (OperationCanceledException) { }
        catch (Exception e) when (e is not OutOfMemoryException) { }
    }

    private void ApplyIcon(string id, AtlasIcon icon)
    {
        Microsoft.UI.Xaml.Media.ImageSource image;
        try { image = ProgramRow.ToImage(icon); }
        catch (Exception e) when (e is ArgumentException or InvalidOperationException or IOException) { return; } // Keeps the tile.
        _icons[id] = image;
        if (_byId.TryGetValue(id, out var row)) row.SetIcon(image);
        if (_current is not null && _current.Entry.ProgramId == id) ShowDetailsTile(_current);
    }

    private async Task RunSizesAsync(IEngineClient engine, List<string> ids, CancellationToken ct)
    {
        try
        {
            for (var i = 0; i < ids.Count; i += SizeChunk)
            {
                ct.ThrowIfCancellationRequested();
                var chunk = ids.GetRange(i, Math.Min(SizeChunk, ids.Count - i));
                await engine.MeasureSizesAsync(chunk, batch => DispatcherQueue.TryEnqueue(() => { if (!ct.IsCancellationRequested) ApplySizes(batch); }), ct);
            }
        }
        catch (OperationCanceledException) { return; }
        catch (Exception e) when (e is not OutOfMemoryException) { }
        // Back on the page's thread (the call came back through its context).
        if (ct.IsCancellationRequested) return;
        _sizing = false;
        if (_sortKey == "size") Refresh();
        UpdateSummary();
    }

    private void ApplySizes(IReadOnlyList<Purge.Client.Rpc.ProgramSize> batch)
    {
        foreach (var size in batch)
        {
            _sizesDone++;
            if (size.Bytes is not { } bytes) continue;
            _sizes[size.ProgramId] = (long)bytes;
            if (_byId.TryGetValue(size.ProgramId, out var row)) row.SetSize((long)bytes);
        }
        UpdateBars();
        UpdateSummary();
        if (_current is not null) ShowDetailsSize(_current);
    }

    /// <summary>Patches that came after the list reply: applied to the rows, which move between tabs when they change.</summary>
    private void OnLatePatches(IReadOnlyList<Purge.Client.Rpc.ProgramPatch> patches) =>
        DispatcherQueue.TryEnqueue(() =>
        {
            if (_doc is null) return;
            var changed = false;
            foreach (var patch in patches)
            {
                if (!_byId.TryGetValue(patch.ProgramId, out var row)) continue;
                row.Update(ProgramEntries.Apply(row.Entry, patch));
                changed = true;
            }
            if (!changed) return;
            _doc = _doc with { Entries = _all.Select(r => r.Entry).ToList() };
            if (_firstTickDone) UpdateTabCounts();
            Refresh();
        });

    /// <summary>Shows the "removed outside Purge" group from <c>inventory.changes</c> once, when there is something in it.</summary>
    private async Task ShowRemovedAsync(Task<Purge.Client.Rpc.InventoryChanges?>? asked)
    {
        if (_changesShown || asked is null) return;
        _changesShown = true;
        var changes = await asked;
        if (changes is null || changes.Disappeared.Count == 0) return;
        var can = Program.Engine.CanChangePc;
        var hint = can ? "Looks for what it left on the PC" : "Needs the Purge security prompt, which this build doesn't have yet";
        FindName(nameof(Attention));
        var live = Program.Engine.IsLive;
        var more = changes.Disappeared.Count - MaxRemovedShown;
        AttentionHeader.Text = "\uE7BA  REMOVED OUTSIDE PURGE · " + changes.Disappeared.Count.ToString(CultureInfo.CurrentCulture)
                               + (more > 0 ? $" (showing {MaxRemovedShown})" : "") + (live ? "" : "   SAMPLE DATA");
        AttentionList.ItemsSource = changes.Disappeared.Take(MaxRemovedShown).Select(p => new RemovedRow(p, can, hint)).ToList();
        UpdateSummary();
    }

    private void OnCheckRemoved(object sender, RoutedEventArgs e) =>
        ShowNotice("Checking a removed program for leftovers needs the Purge security prompt, which this build doesn't have yet.");

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
        if (_forecasts.Count >= _all.Count && _forecasts.Values.Any(f => f is not null))
            text += $" · {apps.Count(r => r.Verdict is ForecastVerdict.Some or ForecastVerdict.Large)} would leave leftovers";
        Summary.Text = text;
        if (_firstTickDone && AllAppsLabel is not null)
            AllAppsLabel.Text = $"ALL {TabLabel(_tab).ToUpper(CultureInfo.CurrentCulture)} · {(ProgramList.ItemsSource as List<ProgramRow>)?.Count ?? 0}";
        UpdateStatus();
    }

    private void UpdateStatus()
    {
        if (!_firstTickDone) return;
        var shown = ProgramList.ItemsSource as List<ProgramRow> ?? [];
        StatusLeft.Text = $"{shown.Count} {TabLabel(_tab).ToLower(CultureInfo.CurrentCulture)} · {ProgramRow.FormatSize(shown.Sum(r => r.SizeBytes ?? 0))}";
        var engine = Program.Engine;
        var right = engine.IsLive ? "Engine connected" : "Sample data · engine not connected";
        if (engine.IsLive && _sizing && _all.Count > 0) right += $" · measuring sizes {Math.Min(_sizesDone, _all.Count)} of {_all.Count}";
        if (LaunchMarkers.Get("list_reply") is { } reply) right += $" · list in {reply.ToString("F0", CultureInfo.CurrentCulture)} ms";
        if (LaunchMarkers.Get("presented") is { } ms) right += $" · on screen in {ms.ToString("F0", CultureInfo.CurrentCulture)} ms";
        StatusRight.Text = right;
    }

    private static string TabLabel(ProgramTab tab) => tab switch
    {
        ProgramTab.Apps => "Apps",
        ProgramTab.Components => "Components",
        ProgramTab.Unnamed => "Unnamed",
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

    // Child rows (updates, Burn children) stay directly under their parent.
    private IEnumerable<ProgramRow> Order<TKey>(IEnumerable<ProgramRow> rows, Func<ProgramRow, TKey> key) =>
        ProgramRules.Order(rows, r => r.Entry, key, _sortDescending);

    private static string KeyName(string keyPath) => ProgramRules.KeyName(keyPath);

    private void UpdateTabCounts()
    {
        TabAppsCount.Text = _all.Count(r => r.IsApp).ToString(CultureInfo.CurrentCulture);
        TabComponentsCount.Text = _all.Count(r => r.IsComponent).ToString(CultureInfo.CurrentCulture);
        TabUnnamedCount.Text = _all.Count(r => r.IsUnnamed).ToString(CultureInfo.CurrentCulture);
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
        // Built on first use (A9.2 step 3).
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
        UninstallLabel.Text = n > 1 ? $"Uninstall {n}" : "Uninstall";
    }

    /// <summary>
    /// Uninstall asks for the broker on the click; until the engine is live the buttons are disabled and the tooltip
    /// says why. Sample data has no engine to ask at all.
    /// </summary>
    private void UpdateCommandState()
    {
        var engine = Program.Engine;
        var can = engine.CanChangePc;
        UninstallButton.IsEnabled = can;
        ToolTipService.SetToolTip(UninstallButton, can ? null : UninstallHint(engine));
        if (DUninstallButton is not null)
        {
            DUninstallButton.IsEnabled = can;
            ToolTipService.SetToolTip(DUninstallButton, can ? null : UninstallHint(engine));
        }
    }

    private static string UninstallHint(IEngineClient engine) => engine.IsLive
        ? "The engine is not usable, so an uninstaller cannot be routed."
        : "Sample data: no engine is connected.";

    private void ShowDetailsTile(ProgramRow row)
    {
        if (!_firstTickDone || Details is null) return;
        DTile.Background = row.HasIcon ? null : row.TileBrush;
        DInitial.Text = row.HasIcon ? "" : row.Initial;
        DIcon.Source = row.Icon;
        DIcon.Visibility = row.HasIcon ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowDetailsSize(ProgramRow row)
    {
        if (!_firstTickDone || Details is null || _current != row) return;
        DSize.Text = row.SizeText.Length > 0 ? row.SizeText : (_sizing ? "Measuring…" : "Not measured");
    }

    private async Task LoadDetailsAsync(ProgramRow row)
    {
        row.DetailsRequested = true;
        try
        {
            var details = await Program.Engine.GetProgramAsync(row.Entry.ProgramId);
            if (details is not null)
            {
                row.Update(ProgramEntries.Apply(row.Entry, details));
                row.DetailsLoaded = true;
            }
            else row.DetailsLoaded = true;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            row.DetailsLoaded = true; // The pane then shows what the list knew; the error is not worth a bar.
        }
        if (_current == row) ShowDetails(row);
    }

    private void ShowDetails(ProgramRow? row)
    {
        // The details pane is created on first use after the first Rendering tick, not for the first frame
        // (A9.2 step 3). Before the tick the row is only remembered in _current and shown by OnFirstTick.
        if (!_firstTickDone) return;
        if (row is null)
        {
            if (Details is not null) Details.Visibility = Visibility.Collapsed;
            return;
        }
        FindName(nameof(Details));
        Details.Visibility = Visibility.Visible;
        UpdateCommandState();
        var e = row.Entry;
        // The list rows carry no uninstaller, folder or product code: programs.get brings them, once per row.
        var engine = Program.Engine;
        if (!engine.IsLive) row.DetailsLoaded = true;
        else if (!row.DetailsRequested) _ = LoadDetailsAsync(row);
        var reading = !row.DetailsLoaded;
        ShowDetailsTile(row);
        DName.Text = row.Name;
        DSub.Text = Join(" · ", row.Publisher, row.Version, row.KindChip);
        DUninstaller.Text = reading
            ? "Reading…"
            : e.UninstallString is null
                ? "None registered"
                : row.KindText + (e.QuietUninstallString is not null || e.InstallerKind == InstallerKind.Msi ? " · quiet mode available" : "");
        DLocation.Content = reading ? "Reading…" : e.InstallLocation ?? "Not recorded";
        DLocation.IsEnabled = e.InstallLocation is not null;
        DInstalled.Text = Join(" · ", row.InstalledText, "for " + row.ScopeText);
        ShowDetailsSize(row);
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

        DUninstall.Text = reading ? "…" : e.UninstallString ?? "None";
        DQuiet.Text = reading ? "…" : e.QuietUninstallString ?? "None";
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
    /// steps its button takes. Force remove, Modify and Remove entry are not offered in M3 (design 10).
    /// </summary>
    public void RunCommand(string tag)
    {
        switch (tag)
        {
            case "more-pending":
                // Clicked before the first tick finished: load the CommandBar now and open its overflow.
                FindName(nameof(Commands));
                PlainCommands.Visibility = Visibility.Collapsed;
                Commands.IsOpen = true;
                return;
            case "open-folder" when _current?.Entry.InstallLocation is { } dir && Directory.Exists(dir):
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = false });
                return;
            case "open-folder":
                ShowNotice("The install folder is not recorded for this program, or is not on this PC any more.");
                return;
            case "web" when _current is { } found:
                Process.Start(new ProcessStartInfo("https://www.bing.com/search?q=" + Uri.EscapeDataString(Join(" ", found.Name, found.Publisher)))
                {
                    UseShellExecute = true,
                });
                return;
            case "refresh" when Program.Engine.IsLive:
                _ = ReloadAsync();
                return;
            case "uninstall" when Program.Engine.CanChangePc && _current is { } row:
                MainWindow.Instance.OpenUninstall().Begin(new UninstallTarget(row.Entry.ProgramId, row.Name));
                return;
        }
        ShowNotice(UninstallHint(Program.Engine));
    }

    /// <summary>Reads the program list from the engine again (after an uninstall, or Refresh list).</summary>
    public async Task ReloadAsync()
    {
        try
        {
            _doc = await Program.Engine.ListProgramsAsync();
            Rebuild();
            StartEnrichment();
        }
        catch (Exception e)
        {
            ShowNotice("Couldn't read the program list: " + e.Message);
        }
    }

    /// <summary>Shows why the engine could not be used (startup).</summary>
    public void ShowEngineNotice(string message) => ShowNotice(message);

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
