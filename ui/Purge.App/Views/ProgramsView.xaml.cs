using System.Diagnostics;
using System.Globalization;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Purge.App.Shell;
using Purge.Client;
using Purge.Client.Broker;
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

/// <summary>
/// A program the stored list had and the registry no longer has ("removed outside Purge", 7a delta 5). Only a program
/// Purge recorded gets "Check for leftovers"; without a record no leftover count is claimed and no scan is offered.
/// </summary>
public sealed partial class RemovedRow(Purge.Client.Rpc.ProgramRef program) : System.ComponentModel.INotifyPropertyChanged
{
    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    public string ProgramId { get; } = program.ProgramId;
    public string Name { get; } = program.Name;
    public string Initial { get; } = program.Name.Length > 0 && char.IsLetterOrDigit(program.Name[0]) ? char.ToUpperInvariant(program.Name[0]).ToString() : "?";

    public string Detail { get; private set; } = "";
    public string ButtonText { get; private set; } = "Check for leftovers";
    public Visibility ButtonVisibility { get; private set; } = Visibility.Collapsed;
    public bool CanCheck { get; private set; }
    public string? CheckHint { get; private set; }
    public bool CanDismiss { get; private set; } = true;

    /// <summary>
    /// Draws the row from the controller's state of it. <paramref name="waitHint"/>: another row's check, the Uninstall
    /// pipeline or a change on the Leftovers page is running, so this row's button waits (one broker at a time) and
    /// the tooltip says for what; null when nothing else runs.
    /// </summary>
    public void Show(RemovedCheckState state, string? waitHint, string? progress, bool canChangePc, string disabledHint)
    {
        var otherBusy = waitHint is not null;
        Detail = state switch
        {
            RemovedCheckState.NoRecord => "Removed outside Purge. Purge did not record what this program installed, so it cannot tell which leftovers are its own.",
            RemovedCheckState.Starting => "Removed outside Purge. Purge is asking for administrator permission…",
            RemovedCheckState.Checking => "Removed outside Purge. Reading Purge's record of it…",
            RemovedCheckState.Scanning => "Looking for what it left" + (progress is { Length: > 0 } p ? " · " + p : "…"),
            _ => "Removed outside Purge. Purge recorded it before, so it can look for what it left.",
        };
        var running = state is RemovedCheckState.Checking or RemovedCheckState.Scanning;
        CanDismiss = state is not (RemovedCheckState.Starting or RemovedCheckState.Checking or RemovedCheckState.Scanning);
        ButtonVisibility = state == RemovedCheckState.NoRecord ? Visibility.Collapsed : Visibility.Visible;
        ButtonText = running ? "Stop" : "Check for leftovers";
        CanCheck = running || (state == RemovedCheckState.Record && canChangePc && !otherBusy);
        CheckHint = running
            ? "Stops the check; nothing is changed"
            : !canChangePc
                ? disabledHint
                : waitHint ?? "Asks for administrator permission, then looks for what it left on the PC";
        foreach (var name in new[] { nameof(Detail), nameof(ButtonText), nameof(ButtonVisibility), nameof(CanCheck), nameof(CheckHint), nameof(CanDismiss) })
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
    }
}

public sealed partial class ProgramsView : UserControl
{
    private const int ForecastBatch = 8;
    private const int SizeChunk = 16;

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
    // The ticked programs by id. A filter, a tab, a search or a re-list hides rows but does not untick them; the list's
    // own selection is redrawn from this set (Show).
    private readonly HashSet<string> _ticked = new(StringComparer.Ordinal);
    private readonly (RadioButton Button, Border Selection, TextBlock Label, TextBlock Count, ProgramTab Tab)[] _tabs;

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

    /// <summary>
    /// Bench only, called at the end of the window constructor: <c>first_row</c> fires in the pre-layout of the page
    /// (<c>MainWindow.PreMeasurePrograms</c>), before the window is shown, so it no longer says the first frame has rows.
    /// <c>first_row_live</c> is the first layout pass after the constructor (the live layout <c>Activate()</c> starts)
    /// that finds a realized row container in the list.
    /// </summary>
    public void WatchLiveRows()
    {
        if (LaunchMarkers.Enabled) ProgramList.LayoutUpdated += OnLiveLayout;
    }

    private void OnLiveLayout(object? sender, object e)
    {
        if (RealizedRows() == 0) return;
        ProgramList.LayoutUpdated -= OnLiveLayout;
        LaunchMarkers.Mark("first_row_live");
    }

    /// <summary>Bench only, at <c>first_tick</c>: <c>rows_at_tick</c>, the number of realized row containers (a count, not a time).</summary>
    public void RecordRowsAtTick()
    {
        if (LaunchMarkers.Enabled) LaunchMarkers.Record("rows_at_tick", RealizedRows());
    }

    /// <summary>Row containers of the list that have been laid out.</summary>
    private int RealizedRows() =>
        ProgramList.ItemsPanelRoot is { } panel ? panel.Children.Count(c => c.ActualSize.Y > 0) : 0;

    /// <summary>The icon atlas file: the user's, or a bench run's own (<c>PURGE_BENCH_ICON_ATLAS</c>, bench only).</summary>
    private static string? BenchAtlasFile() =>
        LaunchMarkers.Enabled && Environment.GetEnvironmentVariable("PURGE_BENCH_ICON_ATLAS") is { Length: > 0 } file ? file : null;

    /// <summary>All rows, for the command box in the title bar.</summary>
    public IReadOnlyList<ProgramRow> All => _all;

    /// <summary>
    /// The rows of a <c>programs.list</c> reply and the list the view first shows (Apps tab, no search or filter,
    /// by name), built off the UI thread as soon as the reply is in (M3 launch perf). <see cref="Load"/> uses them
    /// when the view is still in that default state; otherwise it builds the rows itself.
    /// </summary>
    public sealed class PreparedList(InventoryDoc doc, List<ProgramRow> all, List<ProgramRow> shown)
    {
        public InventoryDoc Doc { get; } = doc;
        public List<ProgramRow> All { get; } = all;
        public List<ProgramRow> Shown { get; } = shown;
    }

    /// <summary>Builds the rows of <paramref name="doc"/> the way <see cref="Rebuild"/> and the default <see cref="Refresh"/> do.
    /// Any thread: rows create no XAML objects until they are shown.</summary>
    public static PreparedList Prepare(InventoryDoc doc)
    {
        var today = DateTime.Today;
        var all = doc.Entries.Select(e => new ProgramRow(e, null, today)).ToList();
        var shown = Arrange(all, ProgramTab.Apps, "", false, false, false, "name", false);
        return new PreparedList(doc, all, shown);
    }

    /// <summary>Takes the <c>programs.list</c> reply. Called before Activate() when it has already arrived.</summary>
    public void Load(StartupResult data, PreparedList? prepared = null)
    {
        _doc = data.Inventory;
        _startup = data;
        if (!_patchesHooked)
        {
            _patchesHooked = true;
            data.Engine.ProgramsPatched += OnLatePatches;
        }
        UpdateCommandState();
        var fresh = prepared is not null && ReferenceEquals(prepared.Doc, data.Inventory) && _all.Count == 0 && _sizes.Count == 0
                    && _icons.Count == 0 && _forecasts.Count == 0 && _current is null && _tab == ProgramTab.Apps && _query.Length == 0
                    && _sortKey == "name" && !_sortDescending && !_onlyLeftovers && !_onlyPerUser && !_only32;
        Rebuild(fresh ? prepared : null);
        // The list can arrive after the first tick; then what the tick would have started starts here.
        if (_firstTickDone) StartAfterFirstFrame();
    }

    private void Rebuild(PreparedList? prepared = null)
    {
        if (_doc is null) return;
        var today = DateTime.Today;
        var currentId = _current?.Entry.ProgramId;
        _all = prepared?.All ?? _doc.Entries.Select(e => new ProgramRow(e, _sizes.TryGetValue(e.ProgramId, out var s) ? s : null, today)).ToList();
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
        _ticked.RemoveWhere(id => !_byId.ContainsKey(id));
        if (_firstTickDone) UpdateTabCounts();
        UpdateSummary();
        MainWindow.Instance.SetProgramsCount(_all.Count);
        if (prepared is not null) Show(prepared.Shown);
        else Refresh();
    }

    private void UpdateBars()
    {
        _maxSize = Math.Max(1, _all.Select(r => r.SizeBytes ?? 0).DefaultIfEmpty(0).Max());
        foreach (var r in _all)
            r.BarWidth = r.SizeBytes is { } b and > 0 ? Math.Max(2, 96.0 * b / _maxSize) : 0;
    }

    /// <summary>Work deferred to after the first Rendering tick (A9.2 step 3).</summary>
    public void OnFirstTick()
    {
        _firstTickDone = true;
        // The ListView default container transitions, left out of the first frame (see the XAML). The items panel
        // (ItemsStackPanel) takes them from the ListView, not from its own ChildrenTransitions, which stay empty here
        // and on fa3ba36 alike; screen captures after a tab switch show the same ~600 ms row animation as fa3ba36.
        ProgramList.ItemContainerTransitions =
        [
            new AddDeleteThemeTransition(),
            new ContentThemeTransition(),
            new ReorderThemeTransition(),
            new EntranceThemeTransition { IsStaggeringEnabled = false },
        ];
        UpdateTabCounts();
        LoadCommands();
        PlainCommands.Visibility = Visibility.Collapsed;
        UpdateCommandState();
        FindName(nameof(SearchBox));
        var find = new Microsoft.UI.Xaml.Input.KeyboardAccelerator { Key = Windows.System.VirtualKey.F, Modifiers = Windows.System.VirtualKeyModifiers.Control };
        find.Invoked += (_, args) =>
        {
            args.Handled = true;
            FocusSearch();
        };
        KeyboardAccelerators.Add(find);
        KeyboardAcceleratorPlacementMode = Microsoft.UI.Xaml.Input.KeyboardAcceleratorPlacementMode.Hidden;
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
        var engine = Program.Engine;
        var group = new RemovedGroup(changes.Disappeared, ids => engine.ForgetRemovedAsync(ids));
        // A program Purge uninstalled while the answer was on its way is not one that went outside Purge.
        foreach (var id in _uninstalledHere) group.Acknowledge(id);
        if (group.IsEmpty) return;
        var removed = _removed ??= NewRemovedController();
        // Which of them Purge may have a fingerprint for: a file-system lookup by name, no prompt (FingerprintStore).
        // Rows that move up when others leave the group are probed when they are first drawn (StateOf).
        await Task.Run(() => removed.Classify(group.Shown.Select(p => p.ProgramId)));
        _group = group;
        FindName(nameof(Attention));
        ShowRemovedRows();
    }

    /// <summary>
    /// Draws the group from <see cref="_group"/>: the header count, the rows still in it (a row keeps its object, so a
    /// running check's row is not redrawn from scratch), and nothing at all once it is empty.
    /// </summary>
    private void ShowRemovedRows()
    {
        if (_group is not { } group || Attention is null) return;
        if (group.IsEmpty)
        {
            Attention.Visibility = Visibility.Collapsed;
            _removedRows = [];
            AttentionList.ItemsSource = null;
            UpdateSummary();
            return;
        }
        // The warning glyph is a FontIcon beside this text (in the text font it drew as an empty box).
        AttentionHeader.Text = group.Header(Program.Engine.IsLive);
        var old = _removedRows.ToDictionary(r => r.ProgramId, StringComparer.Ordinal);
        _removedRows = group.Shown.Select(p => old.TryGetValue(p.ProgramId, out var kept) ? kept : new RemovedRow(p)).ToList();
        AttentionList.ItemsSource = _removedRows;
        RenderRemoved();
        UpdateSummary();
    }

    /// <summary>The user has dealt with a removed program (checked or dismissed it, or Purge uninstalled it): it leaves the group.</summary>
    private void AcknowledgeRemoved(string programId)
    {
        if (_group?.Acknowledge(programId) == true) ShowRemovedRows();
    }

    private void OnDismissRemoved(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string id }) return;
        if (_removed is { } removed && !removed.CanDismiss(id)) return;
        AcknowledgeRemoved(id);
    }

    /// <summary>
    /// The Uninstall page's uninstaller ran and the broker checked the program. When Purge removed it
    /// (<paramref name="removedByPurge"/>), the engine forgets it, so no later session lists it as removed outside Purge.
    /// The list is then read again, so the program leaves it now and the stored list agrees; a program still in the
    /// registry stays.
    /// </summary>
    public async Task OnUninstallRunEndedAsync(string programId, bool removedByPurge)
    {
        var engine = Program.Engine;
        if (!engine.IsLive) return;
        if (removedByPurge)
        {
            _uninstalledHere.Add(programId);
            if (_group?.Contains(programId) == true) AcknowledgeRemoved(programId);
            else
            {
                try { await engine.ForgetRemovedAsync([programId]); }
                catch (Exception e) when (e is not OutOfMemoryException) { }
            }
        }
        await ReloadAsync();
    }

    private RemovedGroup? _group;
    private readonly HashSet<string> _uninstalledHere = new(StringComparer.Ordinal);
    private RemovedLeftoversController? _removed;
    private List<RemovedRow> _removedRows = [];
    private RemovedNotice? _removedNoticeShown;

    private RemovedLeftoversController NewRemovedController()
    {
        var controller = new RemovedLeftoversController(id => FingerprintStore.MayHaveRecord(id), LaunchStoredAsync);
        controller.Changed += () => DispatcherQueue.TryEnqueue(RenderRemoved);
        // A cancelled or declined admin prompt comes back as the controller's Notice, shown in this page's bar.
        controller.Completed += outcome => DispatcherQueue.TryEnqueue(() => OpenStoredScan(outcome));
        return controller;
    }

    /// <summary>Starts the elevated broker for a check, as the Uninstall pipeline does (first-elevation explanation, then UAC).</summary>
    private static async Task<StoredLeftoversLaunch> LaunchStoredAsync(CancellationToken ct)
    {
        try
        {
            if (!await MainWindow.Instance.ConfirmFirstElevationAsync())
                return new StoredLeftoversLaunch(UninstallLaunchState.Cancelled, null, "", DeclinedExplanation: true);
            var result = await BrokerLauncher.LaunchAsync(BrokerLauncher.PathBesideApp(), ct);
            var exitCode = result.ExitCode is { } code ? (uint)code : (uint?)null;
            return result.Status switch
            {
                BrokerLaunchStatus.Started when result.Session is { } session =>
                    new StoredLeftoversLaunch(UninstallLaunchState.Started, new StoredLeftoversClient(session), ""),
                BrokerLaunchStatus.Cancelled => new StoredLeftoversLaunch(UninstallLaunchState.Cancelled, null, result.Message),
                BrokerLaunchStatus.NotAdministrator =>
                    new StoredLeftoversLaunch(UninstallLaunchState.NotAdministrator, null, result.Message),
                BrokerLaunchStatus.TimedOut or BrokerLaunchStatus.ServerCheckFailed =>
                    new StoredLeftoversLaunch(UninstallLaunchState.Failed, null, result.Message),
                _ => new StoredLeftoversLaunch(UninstallLaunchState.CannotStart, null, result.Message, exitCode),
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return new StoredLeftoversLaunch(UninstallLaunchState.CannotStart, null, e.Message);
        }
    }

    /// <summary>
    /// The scan from the stored fingerprint, on the Leftovers page, which takes the broker link (the S3 hand-off).
    /// While that page applies another change its link is not replaced: this scan's broker is ended and a bar says so.
    /// </summary>
    private void OpenStoredScan(StoredScanOutcome outcome)
    {
        if (outcome.Session is not { } session) return;
        var request = new LeftoversRequest(outcome.ProgramId, outcome.ProgramName, SessionId: "",
            outcome.Scan.ScanId, outcome.Scan.Mode, Purge.Client.Rpc.RestorePoint.HighRisk, Quiet: false, session);
        if (LeftoversNavigator.TryShow(request))
        {
            // The check finished and its scan is on the Leftovers page: whatever it found, the program has been
            // looked at, so it leaves the group and does not come back in a later session.
            AcknowledgeRemoved(outcome.ProgramId);
            return;
        }
        _ = session.DisposeAsync().AsTask();
        ShowNotice($"The Leftovers page is still applying another change, so the leftovers of {outcome.ProgramName} "
                   + "were not opened. Nothing was changed; check again when it has finished.");
    }

    /// <summary>
    /// The Uninstall pipeline started or finished a step, or the Leftovers page started or finished a change: the
    /// removed rows' buttons follow it.
    /// </summary>
    public void OnBrokerUsersChanged() => RenderRemoved();

    private bool _checkWasRunning;

    private void RenderRemoved()
    {
        UpdateCommandState();
        if (_removed is not { } removed) return;
        var busy = removed.IsBusy;
        if (busy != _checkWasRunning)
        {
            _checkWasRunning = busy;
            MainWindow.Instance.OnCheckRunningChanged();
        }
        var active = removed.ActiveProgram;
        var engine = Program.Engine;
        // One broker at a time: while the Uninstall pipeline runs a step or the Leftovers page applies a change
        // over its link, no check starts.
        var elsewhere = MainWindow.Instance.UninstallBusy
            ? "Waits until the running uninstall has finished"
            : LeftoversNavigator.IsChanging
                ? "Waits until the Leftovers page has finished its change"
                : null;
        foreach (var row in _removedRows)
        {
            var mine = active == row.ProgramId;
            var waitHint = busy && !mine ? "Waits until the running check has finished" : elsewhere;
            row.Show(removed.StateOf(row.ProgramId), waitHint, mine ? removed.ProgressText : null,
                engine.CanChangePc, UninstallHint(engine));
        }
        if (removed.Notice is { } notice && !ReferenceEquals(notice, _removedNoticeShown))
        {
            _removedNoticeShown = notice;
            ShowNotice(notice.Title + " " + notice.Message, notice.Kind switch
            {
                UninstallNoticeKind.Info => InfoBarSeverity.Informational,
                UninstallNoticeKind.Warning => InfoBarSeverity.Warning,
                _ => InfoBarSeverity.Error,
            });
        }
    }

    private void OnCheckRemoved(object sender, RoutedEventArgs e)
    {
        if (_removed is not { } removed || sender is not FrameworkElement { Tag: string id }) return;
        if (removed.IsBusy)
        {
            // The running row's button reads Stop; the others are disabled meanwhile.
            if (removed.ActiveProgram == id) removed.Cancel();
            return;
        }
        if (MainWindow.Instance.UninstallBusy)
        {
            ShowNotice("An uninstall is running. Check for leftovers when it has finished.");
            return;
        }
        if (LeftoversNavigator.IsChanging)
        {
            ShowNotice("The Leftovers page is applying a change. Check for leftovers when it has finished.");
            return;
        }
        var name = _removedRows.FirstOrDefault(r => r.ProgramId == id)?.Name ?? "";
        _ = removed.CheckAsync(id, name);
        UpdateCommandState();
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
        var trimmed = query.Trim();
        if (trimmed == _query) return;
        _query = trimmed;
        if (_firstTickDone) UpdateTabCounts();
        Refresh();
    }

    /// <summary>Ctrl+F: puts the keyboard in the search box, with its text selected.</summary>
    private void FocusSearch()
    {
        if (SearchBox is null) FindName(nameof(SearchBox));
        SearchBox!.Focus(FocusState.Keyboard);
        SearchBox.SelectAll();
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e) => SetSearch(SearchBox.Text);

    /// <summary>Esc clears the search; with nothing to clear it hands the keyboard to the list.</summary>
    private void OnSearchKeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs e)
    {
        if (e.Key != Windows.System.VirtualKey.Escape) return;
        e.Handled = true;
        if (SearchBox.Text.Length > 0) SearchBox.Text = "";
        else ProgramList.Focus(FocusState.Keyboard);
    }

    /// <summary>Selects one program (from the command box) and shows it.</summary>
    public void Reveal(ProgramRow row)
    {
        if (!row.InTab(_tab)) SelectTab(row.IsApp ? ProgramTab.Apps : row.IsComponent ? ProgramTab.Components : ProgramTab.Unnamed);
        if (SearchBox is not null) SearchBox.Text = "";
        _query = "";
        if (_firstTickDone) UpdateTabCounts();
        Refresh();
        _ticked.Clear();
        _ticked.Add(row.Entry.ProgramId);
        ProgramList.SelectedItems.Clear();
        ProgramList.SelectedItem = row;
        ProgramList.ScrollIntoView(row);
        _current = row;
        ShowDetails(row);
    }

    private void Refresh() => Show(Arrange(_all, _tab, _query, _onlyLeftovers, _onlyPerUser, _only32, _sortKey, _sortDescending));

    /// <summary>Whether <paramref name="r"/> passes the Filter menu's choices.</summary>
    private static bool Passes(ProgramRow r, bool onlyLeftovers, bool onlyPerUser, bool only32) =>
        (!onlyLeftovers || r.Verdict is ForecastVerdict.Some or ForecastVerdict.Large)
        && (!onlyPerUser || r.Entry.Scope == InstallScope.User)
        && (!only32 || r.Entry.View == RegistryView.K32);

    /// <summary>The rows the list shows for a tab, search, filters and sort (the UI thread and <see cref="Prepare"/>).</summary>
    private static List<ProgramRow> Arrange(IEnumerable<ProgramRow> all, ProgramTab tab, string query, bool onlyLeftovers, bool onlyPerUser,
                                            bool only32, string sortKey, bool descending)
    {
        var rows = all.Where(r => r.InTab(tab) && r.Matches(query) && Passes(r, onlyLeftovers, onlyPerUser, only32));
        return (sortKey switch
        {
            "publisher" => Order(rows, r => r.Publisher, descending),
            "size" => Order(rows, r => r.SizeBytes ?? -1, descending),
            "junk" => Order(rows, r => r.JunkRank, descending),
            "date" => Order(rows, r => r.Installed ?? DateTime.MinValue, descending),
            _ => Order(rows, r => r.Name, descending),
        }).ToList();
    }

    /// <summary>
    /// Puts <paramref name="list"/> (filtered and sorted) in the list and keeps the ticked rows that are still in it
    /// (by program id: a reload makes new row objects). Nothing is picked for the user: on the first show, or when
    /// the ticked rows left the list, nothing is selected and the details pane stays closed (user feedback: opening
    /// the app or sorting always selected the top entry).
    /// </summary>
    private void Show(List<ProgramRow> list)
    {
        var ticked = new HashSet<string>(_ticked, StringComparer.Ordinal);
        if (_current is not null) ticked.Add(_current.Entry.ProgramId);
        _refreshing = true;
        ProgramList.ItemsSource = list;
        foreach (var row in list.Where(r => ticked.Contains(r.Entry.ProgramId)))
            ProgramList.SelectedItems.Add(row);
        var keep = _current is null ? null : list.FirstOrDefault(r => r.Entry.ProgramId == _current.Entry.ProgramId);
        keep ??= ProgramList.SelectedItems.Count > 0 ? ProgramList.SelectedItems[^1] as ProgramRow : null;
        _refreshing = false;

        _current = keep;
        ShowDetails(keep);
        ShowNoMatch(list.Count == 0 && (_query.Length > 0 || FilterCount > 0));
        UpdateSelectedCount();
        if (_firstTickDone) UpdateSummary();
    }

    // Child rows (updates, Burn children) stay directly under their parent.
    private static IEnumerable<ProgramRow> Order<TKey>(IEnumerable<ProgramRow> rows, Func<ProgramRow, TKey> key, bool descending) =>
        ProgramRules.Order(rows, r => r.Entry, key, descending);

    private static string KeyName(string keyPath) => ProgramRules.KeyName(keyPath);

    private int FilterCount => (_onlyLeftovers ? 1 : 0) + (_onlyPerUser ? 1 : 0) + (_only32 ? 1 : 0);

    /// <summary>The list got wider or narrower: the optional columns that no longer fit go (Name always stays).</summary>
    private void OnListSizeChanged(object sender, SizeChangedEventArgs e)
    {
        var columns = ProgramColumns.Shared;
        if (!columns.Apply(e.NewSize.Width)) return;
        ListHeader.ColumnDefinitions[2].Width = columns.SizeWidth;
        ListHeader.ColumnDefinitions[3].Width = columns.LeftoversWidth;
        ListHeader.ColumnDefinitions[4].Width = columns.InstalledWidth;
        SortSize.Visibility = columns.Fit.Size ? Visibility.Visible : Visibility.Collapsed;
        SortJunk.Visibility = columns.Fit.Leftovers ? Visibility.Visible : Visibility.Collapsed;
        SortDate.Visibility = columns.Fit.Installed ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>
    /// A narrow page: search, filter and sort move under the tabs, the details pane gets narrower and, below 640 px,
    /// goes (the toolbar's Uninstall still works on the ticked programs).
    /// </summary>
    private void OnPageSizeChanged(object sender, SizeChangedEventArgs e)
    {
        var width = e.NewSize.Width;
        var stack = width < 900;
        Grid.SetRow(ToolsPanel, stack ? 1 : 0);
        Grid.SetColumn(ToolsPanel, stack ? 0 : 1);
        Grid.SetColumnSpan(ToolsPanel, stack ? 2 : 1);
        ToolsPanel.HorizontalAlignment = stack ? HorizontalAlignment.Left : HorizontalAlignment.Right;
        var details = width >= 640;
        DetailsColumn.Width = new GridLength(!details ? 0 : width < 1000 ? 280 : 330);
        DetailsCard.Visibility = details ? Visibility.Visible : Visibility.Collapsed;
        Body.ColumnSpacing = details ? 16 : 0;
    }

    /// <summary>"No programs match" over the empty list while a search or a filter finds nothing in this tab.</summary>
    private void ShowNoMatch(bool show)
    {
        if (show && NoMatch is null) FindName(nameof(NoMatch));
        if (NoMatch is null) return;
        NoMatch.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        if (!show) return;
        var filters = FilterCount > 0;
        NoMatchText.Text = _query.Length == 0
            ? $"No programs in {TabLabel(_tab)} match the filters."
            : $"No programs match \u201C{_query}\u201D{(filters ? " and the filters" : "")} in {TabLabel(_tab)}.";
        NoMatchHint.Text = _query.Length == 0
            ? "Turn a filter off, or try another tab."
            : filters
                ? "Try fewer letters, turn a filter off, or press Esc to clear the search."
                : "Try fewer letters, another tab, or press Esc to clear the search.";
    }

    /// <summary>Each tab's count; with a search or a filter on, how many of its programs it would show.</summary>
    private void UpdateTabCounts()
    {
        var matching = _query.Length == 0 && FilterCount == 0
            ? _all
            : _all.Where(r => r.Matches(_query) && Passes(r, _onlyLeftovers, _onlyPerUser, _only32)).ToList();
        TabAppsCount.Text = matching.Count(r => r.IsApp).ToString(CultureInfo.CurrentCulture);
        TabComponentsCount.Text = matching.Count(r => r.IsComponent).ToString(CultureInfo.CurrentCulture);
        TabUnnamedCount.Text = matching.Count(r => r.IsUnnamed).ToString(CultureInfo.CurrentCulture);
        TabRecentCount.Text = matching.Count(r => r.IsRecent).ToString(CultureInfo.CurrentCulture);
    }

    private void OnTab(object sender, RoutedEventArgs e)
    {
        if (sender is not RadioButton { Tag: string tag } || !Enum.TryParse<ProgramTab>(tag, out var tab)) return;
        SelectTab(tab);
        Refresh();
    }

    private void SelectTab(ProgramTab tab)
    {
        _tab = tab;
        foreach (var t in _tabs)
        {
            var on = t.Tab == tab;
            t.Button.IsChecked = on;
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
            var n = FilterCount;
            FilterText.Text = n == 0 ? "Filter" : $"Filter ({n})";
            if (_firstTickDone) UpdateTabCounts();
            Refresh();
        };
        return item;
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshing) return;
        foreach (var row in e.AddedItems.OfType<ProgramRow>()) _ticked.Add(row.Entry.ProgramId);
        foreach (var row in e.RemovedItems.OfType<ProgramRow>()) _ticked.Remove(row.Entry.ProgramId);
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
        var n = _ticked.Count;
        var hidden = n - ProgramList.SelectedItems.Count;
        SelectedCount.Text = n == 0 ? "" : $"{n} selected" + (hidden > 0 ? $" ({hidden} not shown)" : "");
        UninstallLabel.Text = n > 1 ? $"Uninstall {n}" : "Uninstall";
        AutomationProperties.SetName(UninstallButton, n > 1 ? $"Uninstall {n} programs" : _current is { } row ? "Uninstall " + row.Name : "Uninstall");
        UpdateCommandState();
    }

    /// <summary>The programs "Uninstall" acts on: every ticked one (visible ones in list order first), else the details pane's.</summary>
    private List<UninstallTarget> UninstallTargets()
    {
        var shown = ProgramList.ItemsSource as List<ProgramRow> ?? [];
        var rows = shown.Concat(_all).Where(r => _ticked.Contains(r.Entry.ProgramId)).DistinctBy(r => r.Entry.ProgramId).ToList();
        if (rows.Count == 0 && _current is not null) rows.Add(_current);
        return rows.Select(r => new UninstallTarget(r.Entry.ProgramId, r.Name)).ToList();
    }

    /// <summary>
    /// Uninstall asks for the broker on the click; until the engine is live the buttons are disabled and the tooltip
    /// says why. Sample data has no engine to ask at all. While a removed program's leftovers check runs, Uninstall
    /// waits too (one broker at a time).
    /// </summary>
    private void UpdateCommandState()
    {
        var engine = Program.Engine;
        var can = engine.CanChangePc && !CheckRunning;
        var hint = can ? null : CommandHint(engine);
        // The toolbar button needs a program; the details pane's button only shows with one.
        var picked = _current is not null || _ticked.Count > 0;
        UninstallButton.IsEnabled = can && picked;
        ToolTipService.SetToolTip(UninstallButton, hint ?? (picked ? null : "Select a program to uninstall."));
        // The folder and web commands act on the details pane's program.
        if (OpenFolderCommand is not null)
        {
            OpenFolderCommand.IsEnabled = _current?.Entry.InstallLocation is not null;
            WebCommand.IsEnabled = _current is not null;
        }
        if (DUninstallButton is not null)
        {
            DUninstallButton.IsEnabled = can;
            ToolTipService.SetToolTip(DUninstallButton, hint);
        }
    }

    /// <summary>True while a removed program's leftovers check runs (the Uninstall page's actions wait meanwhile).</summary>
    public bool CheckRunning => _removed?.IsBusy == true;

    private string CommandHint(IEngineClient engine) => engine.CanChangePc && CheckRunning
        ? "A leftovers check is running. Uninstall when it has finished."
        : UninstallHint(engine);

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
            DetailsCard.Opacity = 0;
            return;
        }
        FindName(nameof(Details));
        Details.Visibility = Visibility.Visible;
        DetailsCard.Opacity = 1;
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
        DLocationText.Text = reading ? "Reading…" : e.InstallLocation ?? "Not recorded";
        ToolTipService.SetToolTip(DLocation, e.InstallLocation);
        // Kept enabled: disabling the link while it has keyboard focus (the details load while the user tabs through
        // the pane) is a classic WinUI focus crash, and RunCommand("open-folder") already says when there is no folder.
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

    private bool _commandsHooked;

    /// <summary>
    /// Loads the CommandBar (deferred past the first frame) and names its "…" button. The CommandBar's own tooltip
    /// for that button flips to "See less" while the menu is open; it reads "More actions" at all times instead,
    /// set again after each open and close because the CommandBar resets it then.
    /// </summary>
    private void LoadCommands()
    {
        FindName(nameof(Commands));
        if (_commandsHooked || Commands is null) return;
        _commandsHooked = true;
        Commands.Loaded += (_, _) => NameMoreButton();
        Commands.Opened += (_, _) => DispatcherQueue.TryEnqueue(NameMoreButton);
        Commands.Closed += (_, _) => DispatcherQueue.TryEnqueue(NameMoreButton);
    }

    private void NameMoreButton()
    {
        if (FindChild(Commands, "MoreButton") is not Button more) return;
        ToolTipService.SetToolTip(more, "More actions");
        AutomationProperties.SetName(more, "More actions");
    }

    private static DependencyObject? FindChild(DependencyObject parent, string name)
    {
        var count = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChildrenCount(parent);
        for (var i = 0; i < count; i++)
        {
            var child = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetChild(parent, i);
            if (child is FrameworkElement { Name: var n } && n == name) return child;
            if (FindChild(child, name) is { } found) return found;
        }
        return null;
    }

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
                LoadCommands();
                PlainCommands.Visibility = Visibility.Collapsed;
                Commands.IsOpen = true;
                return;
            case "open-folder" when _current?.Entry.InstallLocation is { } dir && Directory.Exists(dir):
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dir}\"") { UseShellExecute = false });
                return;
            case "open-folder" when _current is null:
            case "web" when _current is null:
                ShowNotice("Select a program first.", InfoBarSeverity.Informational);
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
            case "refresh":
                ShowNotice("Sample data: there is no engine to read the list from.", InfoBarSeverity.Informational);
                return;
            case "uninstall" when Program.Engine.CanChangePc && CheckRunning:
                ShowNotice(CommandHint(Program.Engine));
                return;
            case "uninstall" when Program.Engine.CanChangePc && UninstallTargets() is { Count: > 0 } targets:
                // Several ticked: the Uninstall page runs them one after another, each with its own steps.
                MainWindow.Instance.OpenUninstall().Begin(targets);
                return;
            case "uninstall" when Program.Engine.CanChangePc:
                ShowNotice("Select a program to uninstall first.", InfoBarSeverity.Informational);
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

    private void ShowNotice(string message, InfoBarSeverity severity = InfoBarSeverity.Warning)
    {
        foreach (var child in InfoBarHost.Children.OfType<InfoBar>().Where(b => b.Tag is "notice").ToList())
            InfoBarHost.Children.Remove(child);
        var bar = new InfoBar
        {
            Severity = severity, Message = message, IsOpen = true, IsClosable = true, Tag = "notice",
        };
        // Pin to the window theme: code-made InfoBars otherwise take the warning/info fill from the app theme
        // (Windows setting), not from Settings → Appearance.
        bar.RequestedTheme = MainWindow.Instance.ActualTheme;
        bar.Closed += (s, _) => InfoBarHost.Children.Remove(s);
        InfoBarHost.Children.Add(bar);
    }
}
