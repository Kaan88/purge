using System.ComponentModel;
using System.Globalization;
using Purge.App.Shell;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using RpcBand = Purge.Client.Rpc.Band;
using RpcCategory = Purge.Client.Rpc.Category;
using RpcItemKind = Purge.Client.Rpc.ItemKind;
using ProgressDto = Purge.Client.Rpc.Progress;

namespace Purge.App.Views;

/// <summary>The band a row is shown in (the RPC Blocked band is "Protected" in the UI).</summary>
public enum Band { Safe, Likely, Weak, Protected }

/// <summary>The stopgap consent prompt's item kinds; the broker's dialog no longer uses this page.</summary>
public enum LeftoverKind { File, Registry, Task }

/// <summary>The page's states; the list is only interactive in <see cref="Review"/>.</summary>
public enum LeftoversPhase
{
    /// <summary>Nothing scanned yet (or the page was opened from the rail).</summary>
    Empty,
    Scanning,
    Review,
    /// <summary><c>plan.create</c> or <c>plan.execute</c> is running, or the broker's dialog is open.</summary>
    Waiting,
    Result,
    Undone,
    /// <summary>The broker link ended during a change: what happened is unknown, so no result is claimed.</summary>
    Interrupted,
}

/// <summary>
/// One candidate of <c>scan.candidates</c> as the page keeps it. Plain data (no WinUI types) so the
/// view-model tests can drive it without the app.
/// </summary>
public sealed class LeftoverItemModel
{
    public string CandidateId { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public string GroupName { get; init; } = "";
    public Band Band { get; init; }
    public RpcBand WireBand { get; init; }
    public RpcCategory Category { get; init; }
    public RpcItemKind Kind { get; init; }
    public string? OwnerProgram { get; init; }
    public ulong? SizeBytes { get; init; }
    public List<Warning> Warnings { get; init; } = new();
    public bool Preselected { get; init; }

    /// <summary>The user's (or Purge's) tick; only <see cref="Selectable"/> rows may hold one.</summary>
    public bool Checked { get; set; }

    /// <summary><c>plan.create</c> would not bind this item; it is shown as "cannot be quarantined", unticked.</summary>
    public bool Refused { get; set; }

    public string RefusalReason { get; set; } = "";

    /// <summary>Listed in the plan's attention list (the dialog's ⚠ rows).</summary>
    public bool Attention { get; set; }

    public List<string> Evidence { get; set; } = new();
    public List<string> Blockers { get; set; } = new();

    public bool IsUserData => Category == RpcCategory.UserData
                              || Warnings.Any(w => w.Code.Contains("UserData", StringComparison.OrdinalIgnoreCase));

    /// <summary>Blocked items are listed under "Protected" and never ticked.</summary>
    public bool IsProtected => WireBand == RpcBand.Blocked;

    public bool IsWeak => WireBand == RpcBand.Weak;

    /// <summary>
    /// Report-only items are shown, never acted on. The RPC row does not carry the plan action, so this is
    /// read from a warning the broker may attach; <c>plan.create</c>'s refusals remain the authority.
    /// </summary>
    public bool IsReportOnly => Warnings.Any(w => w.Code.Contains("ReportOnly", StringComparison.OrdinalIgnoreCase));

    public bool Selectable => !IsProtected && !IsReportOnly && !Refused;

    public string SizeText => SizeBytes is { } bytes ? FormatSize(bytes) : "";

    public string Why =>
        Blockers.Count > 0 ? Blockers[0]
        : Warnings.Count > 0 ? Warnings[0].Message
        : Refused && RefusalReason.Length > 0 ? RefusalReason
        : Band switch
        {
            Band.Safe => "Safe: nothing points to another installed app",
            Band.Likely => "Likely: matched by the app's own records",
            Band.Weak => "Weak: the name matches only",
            _ => "Protected: kept for information",
        };

    public static string FormatSize(ulong bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }
        return unit == 0
            ? $"{bytes} B"
            : value.ToString(value >= 100 ? "F0" : "F1", CultureInfo.CurrentCulture) + " " + units[unit];
    }
}

/// <summary>One group header: the eight list groups, then the Protected and report-only sections.</summary>
public sealed class LeftoverGroup
{
    public LeftoverGroup(string name, bool isSection = false)
    {
        Name = name;
        IsSection = isSection;
    }

    public string Name { get; }
    public bool IsSection { get; }
    public bool Expanded { get; set; } = true;
    public List<LeftoverItemModel> Items { get; } = new();
    public int VisibleCount => Items.Count;

    /// <summary>Group boxes tick Safe items only (design 9.4); sections have no box.</summary>
    public bool CanTick => !IsSection && Items.Any(i => i.Selectable && i.Band == Band.Safe);

    public ulong Bytes => Items.Aggregate(0UL, (sum, item) => sum + (item.SizeBytes ?? 0));
}

/// <summary>One row of the plan's attention list, rendered from <c>plan.create</c> itself.</summary>
public sealed class AttentionModel
{
    public string CandidateId { get; init; } = "";
    public string DisplayName { get; init; } = "";
    public Band Band { get; init; }
    public RpcItemKind Kind { get; init; }
    public ulong? SizeBytes { get; init; }
    public List<AttentionReason> Reasons { get; init; } = new();

    public string SizeText => SizeBytes is { } bytes ? LeftoverItemModel.FormatSize(bytes) : "";

    public string ReasonsText => string.Join(" · ", Reasons.Select(ReasonText));

    private static string ReasonText(AttentionReason reason) => reason switch
    {
        AttentionReason.UserData => "holds your data",
        AttentionReason.NotPreselected => "you ticked it; Purge did not preselect it",
        AttentionReason.Large => "very large",
        AttentionReason.NoUndo => "cannot be put back",
        AttentionReason.Inside => "inside another item",
        AttentionReason.Name => "its name needed escaping",
        _ => reason.ToString(),
    };
}

/// <summary>
/// The Leftovers page's state machine and rules: paging, tick rules, re-tick after a re-scan,
/// <c>plan.create</c> refusals, the waiting state and the result page (design 6.4, 7a S3, 8.1).
/// It never claims an item was moved before <c>plan.execute</c> returned.
/// <para>
/// Threading: the model is driven from the UI thread and never leaves its context (no <c>ConfigureAwait(false)</c>),
/// and the broker's notifications, which arrive on its reader thread, are posted to the context the model was made
/// on. Every state change and every <see cref="Changed"/> so happens on the UI thread, and the view's refresh never
/// reads the item list while another thread rewrites it.
/// </para>
/// </summary>
public sealed class LeftoversViewModel : INotifyPropertyChanged
{
    /// <summary>The broker's largest <c>scan.candidates</c> page.</summary>
    public const int CandidatePageSize = 500;

    private readonly ILeftoversBroker _broker;
    private readonly Action? _allowForeground;
    private string? _sessionId;
    private string? _programId;
    private bool _forced;
    private HashSet<string>? _rescanTicks;
    private HashSet<string>? _rescanIds;
    private int _asked;
    private bool _busy;
    private readonly SynchronizationContext? _context;

    public LeftoversViewModel(ILeftoversBroker broker, Action? allowForeground = null)
    {
        _broker = broker;
        _allowForeground = allowForeground;
        _context = SynchronizationContext.Current;
        _broker.ConsentShown += shown => OnContext(() => OnConsentShown(shown));
        _broker.BaselineChanged += changed => OnContext(() => OnBaselineChanged(changed));
    }

    /// <summary>Runs a broker notification's handler on the model's context (the UI thread in the app).</summary>
    private void OnContext(Action handler)
    {
        if (_context is { } context && SynchronizationContext.Current != context) context.Post(_ => handler(), null);
        else handler();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Raised after any state change, on the context that drives the model (the UI thread in the app).</summary>
    public event Action? Changed;

    public LeftoversPhase Phase { get; private set; } = LeftoversPhase.Empty;
    public ScanResult? Scan { get; private set; }
    public PlanCreated? Plan { get; private set; }
    public ExecResult? Result { get; private set; }
    public UndoResult? Undo { get; private set; }
    public string ProgramName { get; private set; } = "";

    /// <summary>The code the broker's dialog shows in its footer; null until the plan exists.</summary>
    public string? Code { get; private set; }

    /// <summary>Whether <c>consent.shown</c> has arrived: the broker's dialog is up.</summary>
    public bool PromptUp { get; private set; }

    public string WaitingTitle { get; private set; } = "";
    public string WaitingDetail { get; private set; } = "Nothing has been moved yet.";
    public string ScanProgress { get; private set; } = "";
    public string? Error { get; private set; }
    public string? Info { get; private set; }
    public string? ResultTitle { get; private set; }
    public string? ResultDetail { get; private set; }
    public string? RestorePointText { get; private set; }
    public string? UndoTitle { get; private set; }
    public string? UndoDetail { get; private set; }
    public string? RescanMessage { get; private set; }
    public bool RescanOffered { get; private set; }

    public List<LeftoverItemModel> Items { get; } = new();
    public List<LeftoverGroup> Groups { get; } = new();
    public List<AttentionModel> Attention { get; } = new();
    public List<string> RefusalLines { get; } = new();
    public List<string> HeldLines { get; } = new();
    public List<string> FailedLines { get; } = new();
    public List<string> UndoConflictLines { get; } = new();

    private bool _showWeak;
    /// <summary>Weak matches are hidden by default; the toggle shows them and never ticks them.</summary>
    public bool ShowWeak
    {
        get => _showWeak;
        set
        {
            if (_showWeak == value) return;
            _showWeak = value;
            Notify(nameof(ShowWeak));
        }
    }

    public int WeakCount => Items.Count(i => i.IsWeak);
    public int SelectableCount => Items.Count(i => i.Selectable);
    public int SelectedCount => Items.Count(i => i.Checked && i.Selectable);
    public ulong SelectedBytes => Items.Where(i => i.Checked && i.Selectable).Aggregate(0UL, (sum, item) => sum + (item.SizeBytes ?? 0));
    public string MoveText => SelectedCount == 1 ? "Move 1 item to quarantine…" : $"Move {SelectedCount} items to quarantine…";
    public bool CanMove => Phase == LeftoversPhase.Review && SelectedCount > 0 && !_busy;

    /// <summary>
    /// True while a change is on its way (<c>plan.create</c>, <c>plan.execute</c>, undo or the retry of held items, or
    /// the broker's dialog for one): the page's broker link must not be replaced then.
    /// </summary>
    public bool IsChanging => Phase == LeftoversPhase.Waiting;

    public bool CanUndo => Phase == LeftoversPhase.Result && Result is { Session.Length: > 0 } result
                           && (result.Counts.Done > 0 || result.Counts.Vanished > 0);

    public bool CanRetryHeld => Phase == LeftoversPhase.Result && Result is { Held.Count: > 0 };

    public bool BrokerIsLive => _broker.IsLive;

    /// <summary>The rows the list shows: group filters, weak matches, collapsed groups handled by the view.</summary>
    public List<LeftoverItemModel> VisibleItems(LeftoverGroup group) =>
        group.Items.Where(item => ShowWeak || !item.IsWeak).ToList();

    /// <summary>The groups with at least one visible row.</summary>
    public List<LeftoverGroup> VisibleGroups() =>
        Groups.Where(group => group.Items.Any(item => ShowWeak || !item.IsWeak)).ToList();

    /// <summary>Scans an uninstall session (or a stored fingerprint when <paramref name="sessionId"/> is null).</summary>
    public Task ScanAsync(string? sessionId, string? programId, bool forced, CancellationToken ct = default) =>
        LoadAsync(sessionId, programId, forced, rescan: false, ct);

    /// <summary>
    /// Shows the scan S2 already made: pages <c>scan.candidates</c> for its id and does not ask
    /// <c>leftovers.scan</c> a second time. The session and program are kept so a re-scan can ask again later.
    /// </summary>
    public Task ShowRequestAsync(LeftoversRequest request, CancellationToken ct = default) =>
        ShowScanAsync(request.ScanId, request.Mode, request.ProgramName, request.SessionId, request.ProgramId, ct);

    /// <summary>The hand-off without the page's record, for the view model and its tests.</summary>
    public async Task ShowScanAsync(string scanId, ScanMode mode, string programName, string? sessionId, string? programId,
        CancellationToken ct = default)
    {
        if (_busy) return;
        _busy = true;
        ProgramName = programName;
        _sessionId = sessionId;
        _programId = programId;
        _forced = mode == ScanMode.Forced;
        _rescanTicks = null;
        _rescanIds = null;
        RescanOffered = false;
        RescanMessage = null;
        Error = null;
        Info = null;
        Attention.Clear();
        RefusalLines.Clear();
        Phase = LeftoversPhase.Scanning;
        ScanProgress = "Reading the scan";
        Notify();
        try
        {
            Scan = new ScanResult { ScanId = scanId, Mode = mode };
            await LoadCandidatesAsync(Scan, ct);
            BuildGroups();
            ApplyTicks(null);
            Phase = LeftoversPhase.Review;
            ScanProgress = "";
        }
        catch (OperationCanceledException)
        {
            Phase = LeftoversPhase.Empty;
            Info = "The scan was not loaded.";
        }
        catch (BrokerRpcException ex)
        {
            Phase = LeftoversPhase.Empty;
            Error = DescribeError(ex);
        }
        catch (BrokerLinkException ex)
        {
            Phase = LeftoversPhase.Empty;
            Error = "The administrator part ended before the scan could be shown. " + ex.Message;
        }
        finally
        {
            _busy = false;
            Notify();
        }
    }

    /// <summary>Scans again and re-applies the ticks by <c>CandidateId</c> (design 3.6).</summary>
    public Task RescanAsync(CancellationToken ct = default)
    {
        if (Scan is null) return Task.CompletedTask;
        return LoadAsync(_sessionId, _programId, _forced, rescan: true, ct);
    }

    private async Task LoadAsync(string? sessionId, string? programId, bool forced, bool rescan, CancellationToken ct)
    {
        if (_busy) return;
        _busy = true;
        _sessionId = sessionId;
        _programId = programId;
        _forced = forced;
        RescanOffered = false;
        RescanMessage = null;
        if (rescan)
        {
            _rescanTicks = Items.Where(i => i.Checked && i.Selectable).Select(i => i.CandidateId).ToHashSet(StringComparer.Ordinal);
            _rescanIds = Items.Select(i => i.CandidateId).ToHashSet(StringComparer.Ordinal);
        }
        else
        {
            _rescanTicks = null;
            _rescanIds = null;
        }
        Error = null;
        Info = null;
        Attention.Clear();
        RefusalLines.Clear();
        Phase = LeftoversPhase.Scanning;
        ScanProgress = "Starting the scan";
        Notify();
        try
        {
            var activity = new Progress<ProgressDto>(p =>
            {
                ScanProgress = p.Phase;
                Changed?.Invoke();
            });
            var scan = sessionId is { Length: > 0 }
                ? await _broker.ScanSessionAsync(sessionId, forced, activity, ct)
                : await _broker.ScanStoredAsync(programId ?? "", activity, ct);
            Scan = scan;
            await LoadCandidatesAsync(scan, ct);
            BuildGroups();
            ApplyTicks(_rescanTicks);
            if (rescan) DescribeRescan();
            Phase = LeftoversPhase.Review;
            ScanProgress = "";
        }
        catch (OperationCanceledException)
        {
            Phase = LeftoversPhase.Empty;
            Info = "The scan was cancelled.";
        }
        catch (BrokerRpcException ex)
        {
            Phase = LeftoversPhase.Empty;
            Error = DescribeError(ex);
        }
        catch (BrokerLinkException ex)
        {
            Phase = LeftoversPhase.Empty;
            Error = "The administrator part ended before the scan finished. " + ex.Message;
        }
        finally
        {
            _busy = false;
            Notify();
        }
    }

    private async Task LoadCandidatesAsync(ScanResult scan, CancellationToken ct)
    {
        Items.Clear();
        uint offset = 0;
        var total = uint.MaxValue;
        while (offset < total)
        {
            var page = await _broker.CandidatesAsync(scan.ScanId, offset, CandidatePageSize, ct);
            total = page.Total;
            if (page.Items.Count == 0) break;
            foreach (var candidate in page.Items) Items.Add(ToModel(candidate));
            offset += (uint)page.Items.Count;
        }
    }

    private static LeftoverItemModel ToModel(CandidateRow row) => new()
    {
        CandidateId = row.CandidateId,
        DisplayName = row.DisplayName,
        GroupName = GroupNameOf(row),
        Band = Look(row.Band),
        WireBand = row.Band,
        Category = row.Category,
        Kind = row.Kind,
        OwnerProgram = row.OwnerProgram,
        SizeBytes = row.SizeBytes,
        Warnings = row.Warnings,
        Preselected = row.Preselected,
        Checked = row.Preselected,
    };

    private static Band Look(RpcBand band) => band switch
    {
        RpcBand.Safe => Band.Safe,
        RpcBand.Likely => Band.Likely,
        RpcBand.Weak => Band.Weak,
        _ => Band.Protected,
    };

    private static string GroupNameOf(CandidateRow row) => GroupNameOf(row.Category, row.Kind);

    private static string GroupNameOf(RpcCategory category, RpcItemKind kind)
    {
        if (category == RpcCategory.Association) return "File associations & protocols";
        if (category == RpcCategory.ShellCom) return "Shell & COM";
        if (category == RpcCategory.Privacy) return "Privacy traces";
        if (category == RpcCategory.Package || kind == RpcItemKind.Package) return "Packages";
        if (kind is RpcItemKind.Service or RpcItemKind.Task || category == RpcCategory.Startup) return "Services, tasks & other";
        if (kind == RpcItemKind.FirewallRule) return "Firewall rules";
        if (category == RpcCategory.Registration || kind is RpcItemKind.RegistryKey or RpcItemKind.RegistryValue or RpcItemKind.RegistryData)
            return "Registry";
        return "Files & folders";
    }

    private static readonly string[] GroupOrder =
    [
        "Files & folders",
        "Registry",
        "File associations & protocols",
        "Shell & COM",
        "Services, tasks & other",
        "Firewall rules",
        "Packages",
        "Privacy traces",
    ];

    private void BuildGroups()
    {
        Groups.Clear();
        foreach (var name in GroupOrder)
        {
            var items = Items.Where(i => i.GroupName == name && !i.IsProtected && !i.IsReportOnly).ToList();
            if (items.Count == 0) continue;
            var group = new LeftoverGroup(name);
            group.Items.AddRange(items);
            Groups.Add(group);
        }
        var protectedItems = Items.Where(i => i.IsProtected).ToList();
        if (protectedItems.Count > 0)
        {
            var group = new LeftoverGroup("Protected — never removed", isSection: true);
            group.Items.AddRange(protectedItems);
            Groups.Add(group);
        }
        var reportOnly = Items.Where(i => !i.IsProtected && i.IsReportOnly).ToList();
        if (reportOnly.Count > 0)
        {
            var group = new LeftoverGroup("Report only — shown, never removed", isSection: true);
            group.Items.AddRange(reportOnly);
            Groups.Add(group);
        }
    }

    private void ApplyTicks(HashSet<string>? ticks)
    {
        // The broker never preselects in a forced scan; do not invent ticks if a server ever did.
        var preselects = Scan?.Mode != ScanMode.Forced;
        foreach (var item in Items)
        {
            item.Refused = false;
            item.RefusalReason = "";
            item.Checked = ticks is null
                ? preselects && item.Preselected && item.Selectable
                : ticks.Contains(item.CandidateId) && item.Selectable;
        }
    }

    private void DescribeRescan()
    {
        if (_rescanTicks is null || _rescanIds is null) return;
        var ids = Items.Select(i => i.CandidateId).ToHashSet(StringComparer.Ordinal);
        var newItems = Items.Count(i => !_rescanIds.Contains(i.CandidateId));
        var gone = _rescanIds.Count(id => !ids.Contains(id));
        var goneTicked = _rescanTicks.Count(id => !ids.Contains(id));
        RescanMessage = newItems == 0 && gone == 0
            ? "Scanned again. The list is unchanged; your ticks were kept."
            : $"Scanned again. {newItems} new {(newItems == 1 ? "item" : "items")}, " +
              $"{gone} gone ({goneTicked} of them ticked); your ticks were kept by item id.";
    }

    /// <summary>Ticks or unticks one row; Likely and user-data rows need their own tick (design 9.4).</summary>
    public void SetChecked(LeftoverItemModel item, bool value)
    {
        if (!item.Selectable) return;
        item.Checked = value;
        NotifyCounts();
    }

    /// <summary>A group box ticks the group's Safe items only; a second click unticks the group.</summary>
    public void ToggleGroup(LeftoverGroup group)
    {
        if (!group.CanTick) return;
        var selectable = group.Items.Where(i => i.Selectable).ToList();
        var all = selectable.Count > 0 && selectable.All(i => i.Checked);
        foreach (var item in group.Items)
        {
            if (all) item.Checked = false;
            else if (item.Selectable && item.Band == Band.Safe) item.Checked = true;
        }
        NotifyCounts();
    }

    /// <summary>Fetches <c>candidate.explain</c> for the detail pane.</summary>
    public async Task ExplainAsync(LeftoverItemModel item, CancellationToken ct = default)
    {
        if (Scan is null) return;
        try
        {
            var explanation = await _broker.ExplainAsync(Scan.ScanId, item.CandidateId, ct);
            item.Evidence = explanation.Evidence;
            item.Blockers = explanation.Blockers;
        }
        catch (Exception ex) when (ex is BrokerRpcException or BrokerLinkException)
        {
            item.Blockers = [ex.Message];
        }
    }

    /// <summary>
    /// <c>plan.create</c> then <c>plan.execute</c>. The waiting state names the code from <c>plan.create</c>
    /// and switches when <c>consent.shown</c> says the dialog is up; nothing is said to be moved until the
    /// result arrives.
    /// </summary>
    public async Task MoveAsync(RestorePoint restorePoint = RestorePoint.HighRisk, CancellationToken ct = default)
    {
        if (_busy || Scan is null) return;
        var chosen = Items.Where(i => i.Checked && i.Selectable).ToList();
        if (chosen.Count == 0) return;
        _busy = true;
        _asked = chosen.Count;
        Error = null;
        Info = null;
        RefusalLines.Clear();
        Attention.Clear();
        PromptUp = false;
        Code = null;
        Plan = null;
        Phase = LeftoversPhase.Waiting;
        WaitingTitle = "Preparing the plan…";
        WaitingDetail = "Nothing has been moved yet.";
        Notify();
        try
        {
            PlanCreated plan;
            try
            {
                plan = await _broker.CreatePlanAsync(Scan.ScanId, chosen.Select(i => i.CandidateId).ToList(), ct)
                    ;
            }
            catch (BrokerRpcException ex) when (ex.Kind == "plan_refused")
            {
                ApplyRefusals(ex, chosen.Count);
                Phase = LeftoversPhase.Review;
                return;
            }

            Plan = plan;
            Code = plan.Code;
            ApplyAttention(plan);
            WaitingTitle = "Confirm in the Purge security prompt.";
            WaitingDetail = "Nothing has been moved yet. The prompt names the items and shows the same code.";
            Notify();

            _allowForeground?.Invoke();
            var progress = new Progress<ProgressDto>(p =>
            {
                WaitingDetail = p.Phase;
                Changed?.Invoke();
            });
            var result = await _broker.ExecuteAsync(plan.PlanId, restorePoint, progress, ct);
            Result = result;
            BuildResult(result);
            Phase = LeftoversPhase.Result;
            WaitingTitle = "";
        }
        catch (BrokerRpcException ex) when (ex.Kind == "consent_declined")
        {
            Phase = LeftoversPhase.Review;
            Info = "Nothing was moved: the prompt was cancelled.";
        }
        catch (BrokerLinkException)
        {
            Phase = LeftoversPhase.Interrupted;
            Error = "The administrator part ended during the move. Purge cannot tell which items were moved. " +
                    "Check History & undo before trying again; nothing is claimed here.";
        }
        catch (OperationCanceledException)
        {
            Phase = LeftoversPhase.Review;
            Info = "The move was not started.";
        }
        catch (BrokerRpcException ex)
        {
            Phase = LeftoversPhase.Review;
            Error = DescribeError(ex);
        }
        finally
        {
            _busy = false;
            Notify();
        }
    }

    private void ApplyRefusals(BrokerRpcException error, int chosen)
    {
        var refusals = error.Details?.Refusals ?? [];
        foreach (var refusal in refusals)
        {
            if (refusal.CandidateId is { Length: > 0 } id && Items.FirstOrDefault(i => i.CandidateId == id) is { } item)
            {
                item.Refused = true;
                item.Checked = false;
                item.RefusalReason = refusal.Reason;
                RefusalLines.Add($"{item.DisplayName}: {refusal.Reason}");
            }
            else
            {
                RefusalLines.Add(refusal.CandidateId is { Length: > 0 }
                    ? $"{refusal.CandidateId}: {refusal.Reason}"
                    : refusal.Reason);
            }
        }
        Error = refusals.Count == 0
            ? "The plan was refused."
            : $"{refusals.Count.ToString(CultureInfo.CurrentCulture)} of {chosen.ToString(CultureInfo.CurrentCulture)} selected " +
              "items cannot be quarantined; they are shown unticked. Nothing has been moved.";
    }

    private void ApplyAttention(PlanCreated plan)
    {
        Attention.Clear();
        foreach (var attention in plan.Attention)
        {
            Attention.Add(new AttentionModel
            {
                CandidateId = attention.CandidateId,
                DisplayName = attention.DisplayName,
                Band = Look(attention.Band),
                Kind = attention.Kind,
                SizeBytes = attention.SizeBytes,
                Reasons = attention.Reasons,
            });
            if (Items.FirstOrDefault(i => i.CandidateId == attention.CandidateId) is { } item)
                item.Attention = true;
        }
    }

    private void BuildResult(ExecResult result)
    {
        var counts = result.Counts;
        var moved = counts.Done + counts.Vanished;
        HeldLines.Clear();
        foreach (var held in result.Held)
        {
            var lockers = held.Lockers.Count == 0
                ? "still in use"
                : string.Join(", ", held.Lockers.Select(locker =>
                    locker.Service is { Length: > 0 } service
                        ? $"{locker.Name} (service {service})"
                        : $"{locker.Name} ({locker.Pid.ToString(CultureInfo.CurrentCulture)})"));
            HeldLines.Add($"{held.DisplayName} — held by {lockers}");
        }
        FailedLines.Clear();
        if (counts.Failed > 0)
            FailedLines.Add($"{counts.Failed.ToString(CultureInfo.CurrentCulture)} could not be moved. They are listed in History & undo.");
        if (counts.PendingReboot > 0)
            FailedLines.Add($"{counts.PendingReboot.ToString(CultureInfo.CurrentCulture)} will go at the next restart.");
        if (counts.Skipped > 0)
            FailedLines.Add($"{counts.Skipped.ToString(CultureInfo.CurrentCulture)} were left alone.");

        ResultTitle = result.Outcome switch
        {
            Outcome.NotClosed => "The session was not recorded completely",
            Outcome.Complete => moved == 1 ? "Moved 1 item to quarantine" : $"Moved {moved.ToString(CultureInfo.CurrentCulture)} items to quarantine",
            _ => $"Moved {moved.ToString(CultureInfo.CurrentCulture)} of {_asked.ToString(CultureInfo.CurrentCulture)} items to quarantine",
        };
        var parts = new List<string>();
        if (counts.Done > 0) parts.Add($"{counts.Done.ToString(CultureInfo.CurrentCulture)} moved");
        if (counts.Vanished > 0) parts.Add($"{counts.Vanished.ToString(CultureInfo.CurrentCulture)} already gone");
        if (counts.HeldRetry > 0) parts.Add($"{counts.HeldRetry.ToString(CultureInfo.CurrentCulture)} held for a later try");
        if (counts.Failed > 0) parts.Add($"{counts.Failed.ToString(CultureInfo.CurrentCulture)} failed");
        ResultDetail = string.Join(" · ", parts);
        if (result.Outcome == Outcome.NotClosed)
            ResultDetail += ". History & undo offers recovery.";
        RestorePointText = result.RestorePoint.Kind == "Created"
            ? $"Restore point {result.RestorePoint.Sequence?.ToString(CultureInfo.CurrentCulture)} made before the move."
            : null;
    }

    /// <summary><c>undo.run</c> for everything the result's session moved.</summary>
    public async Task UndoAllAsync(CancellationToken ct = default)
    {
        if (_busy || Result is not { Session.Length: > 0 } result) return;
        _busy = true;
        Error = null;
        Info = null;
        PromptUp = false;
        Code = null;
        Attention.Clear();
        Phase = LeftoversPhase.Waiting;
        WaitingTitle = "Confirm the restore in the Purge security prompt.";
        WaitingDetail = "Nothing has been put back yet.";
        Notify();
        try
        {
            _allowForeground?.Invoke();
            var undoTarget = result.Session;
            var progress = new Progress<ProgressDto>(p =>
            {
                WaitingDetail = p.Phase;
                Changed?.Invoke();
            });
            var undo = await _broker.UndoAsync(undoTarget, progress, ct);
            Undo = undo;
            UndoConflictLines.Clear();
            foreach (var conflict in undo.Conflicts)
                UndoConflictLines.Add(ReconcileAlert.Text(conflict));
            foreach (var alert in undo.Alerts)
                UndoConflictLines.Add(AlertText(alert));
            UndoTitle = undo.Outcome == Outcome.UndoConflicts ? "Put back, with conflicts" : "Put back";
            UndoDetail = undo.Conflicts.Count == 0
                ? "Everything this session moved is back where it was."
                : $"{undo.Conflicts.Count.ToString(CultureInfo.CurrentCulture)} items could not be put back; they are listed below.";
            Phase = LeftoversPhase.Undone;
        }
        catch (BrokerRpcException ex) when (ex.Kind == "consent_declined")
        {
            Phase = LeftoversPhase.Result;
            Info = "Nothing was put back: the prompt was cancelled.";
        }
        catch (BrokerLinkException)
        {
            Phase = LeftoversPhase.Interrupted;
            Error = "The administrator part ended during the restore. Purge cannot tell what was put back; " +
                    "check History & undo.";
        }
        catch (BrokerRpcException ex)
        {
            Phase = LeftoversPhase.Result;
            Error = DescribeError(ex);
        }
        finally
        {
            _busy = false;
            Notify();
        }
    }

    /// <summary><c>journal.retry_held</c>: tries the items a partial run left locked.</summary>
    public async Task RetryHeldAsync(CancellationToken ct = default)
    {
        if (_busy || Result is not { Session.Length: > 0 } result) return;
        _busy = true;
        Error = null;
        Info = null;
        PromptUp = false;
        Code = null;
        Attention.Clear();
        Phase = LeftoversPhase.Waiting;
        WaitingTitle = "Confirm the retry in the Purge security prompt.";
        WaitingDetail = "Nothing has been moved yet.";
        Notify();
        try
        {
            _allowForeground?.Invoke();
            var retried = await _broker.RetryHeldAsync(result.Session, ct);
            Phase = LeftoversPhase.Result;
            Info = retried.Outcome == Outcome.Complete
                ? "The held items were tried again and moved."
                : "The held items were tried again; some are still in use. See History & undo.";
            if (retried.Alerts.Count > 0)
                Info = string.Join(" ", retried.Alerts.Select(AlertText).Prepend(Info));
        }
        catch (BrokerRpcException ex) when (ex.Kind == "consent_declined")
        {
            Phase = LeftoversPhase.Result;
            Info = "Nothing was tried: the prompt was cancelled.";
        }
        catch (BrokerLinkException)
        {
            Phase = LeftoversPhase.Interrupted;
            Error = "The administrator part ended during the retry. Purge cannot tell what was moved; " +
                    "check History & undo.";
        }
        catch (BrokerRpcException ex)
        {
            Phase = LeftoversPhase.Result;
            Error = DescribeError(ex);
        }
        finally
        {
            _busy = false;
            Notify();
        }
    }

    /// <summary>Sample rows for <c>--sample</c> and the Settings preview; <paramref name="count"/> above zero loads the
    /// <see cref="LeftoversSample.Fixture"/> of that many items instead (the launch bench's S3 timer).</summary>
    public void LoadSample(string name = "Mozilla Firefox", int count = 0)
    {
        ProgramName = name;
        Items.Clear();
        Items.AddRange(count > 0 ? LeftoversSample.Fixture(count) : LeftoversSample.Items());
        Scan = new ScanResult { ScanId = "sample", Mode = ScanMode.Forced };
        BuildGroups();
        ApplyTicks(null);
        Phase = LeftoversPhase.Review;
        Notify();
    }

    /// <summary>The line a reconcile alert adds to the undone panel (review M3-R2 S5).</summary>
    private static string AlertText(Alert alert) => ReconcileAlert.Text(alert);

    private static string DescribeError(BrokerRpcException error)
    {
        var data = error.Details;
        return error.Kind switch
        {
            "cap_exceeded" =>
                $"The quarantine would pass its cap on {data?.Volume}: {data?.Needed} bytes are needed, " +
                $"{data?.Used} of {data?.Cap} are in use.",
            "needs_recovery" => "An interrupted cleanup comes first. Finish or roll it back from History & undo.",
            "gone" => "This scan has expired. Scan again to get a current list.",
            "busy" => "The administrator part is running another change. Wait for it to finish.",
            "store_integrity" => "The quarantine store failed its check. " + error.Message,
            "plan_refused" => "The plan was refused. " + error.Message,
            _ => error.Message,
        };
    }

    private void OnConsentShown(ConsentShown shown)
    {
        // The dialog's footer is the truth: it is the code the user sees in the elevated prompt.
        PromptUp = true;
        Code = shown.Code;
        Notify();
    }

    private void OnBaselineChanged(BaselineChanged changed)
    {
        if (Scan is { } scan && changed.RescanOffered.Contains(scan.ScanId, StringComparer.Ordinal))
        {
            RescanOffered = true;
            Notify();
        }
    }

    private void NotifyCounts()
    {
        // Counts only: a tick must not rebuild the 2,000-row list. The view updates the footer itself.
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SelectedCount)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(SelectedBytes)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(MoveText)));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CanMove)));
    }

    private void Notify(string? property = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
        Changed?.Invoke();
    }
}

/// <summary>The Firefox sample the stopgap page and the Settings preview use; no scan exists for it.</summary>
public static class LeftoversSample
{
    public static List<LeftoverItemModel> Items() =>
    [
        Item("c-0000000000000001", @"C:\Users\tester\AppData\Local\Mozilla", "Files & folders", Band.Safe, RpcCategory.AppData,
            RpcItemKind.Folder, 2_726_297, preselected: true, why: "App cache · only Firefox data inside · vendor folder"),
        Item("c-0000000000000002", @"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38", "Files & folders", Band.Safe,
            RpcCategory.AppData, RpcItemKind.Folder, 98_304, preselected: true),
        Item("c-0000000000000003", @"C:\Users\tester\AppData\Roaming\Mozilla", "Files & folders", Band.Likely,
            RpcCategory.UserData, RpcItemKind.Folder, 2_202_009),
        Item("c-0000000000000004", @"HKCU\Software\Mozilla\Firefox", "Registry", Band.Safe, RpcCategory.Registration,
            RpcItemKind.RegistryKey, 0, preselected: true),
        Item("c-0000000000000005", @"HKLM\Software\Classes\FirefoxHTML-308046B0AF4A39CB", "File associations & protocols",
            Band.Safe, RpcCategory.Association, RpcItemKind.RegistryKey, 0, preselected: true),
        Item("c-0000000000000006", @"HKLM\Software\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}", "Shell & COM",
            Band.Likely, RpcCategory.ShellCom, RpcItemKind.RegistryKey, 0),
        Item("c-0000000000000007", "Task: Firefox Default Browser Agent 308046B0AF4A39CB", "Services, tasks & other",
            Band.Safe, RpcCategory.Registration, RpcItemKind.Task, 0, preselected: true),
        Item("c-0000000000000008", "Service: Mozilla Maintenance Service", "Services, tasks & other", Band.Likely,
            RpcCategory.Registration, RpcItemKind.Service, 0),
        Item("c-0000000000000009", @"C:\Windows\Prefetch", "Protected — never removed", Band.Protected, RpcCategory.System,
            RpcItemKind.Folder, 0),
        Item("c-000000000000000a", @"C:\Users\tester\AppData\Local\Temp\firefox-crash-reports", "Files & folders",
            Band.Weak, RpcCategory.Cache, RpcItemKind.Folder, 655_360),
    ];

    /// <summary>
    /// <paramref name="count"/> items for the launch bench's S3 timer (M3 design 9.1, "S3 page open, 2,000-item
    /// fixture"): the sample items repeated in order, each copy with its own id and a numbered name, so every group of
    /// the sample, the Protected section included, grows in proportion.
    /// </summary>
    public static List<LeftoverItemModel> Fixture(int count)
    {
        var template = Items();
        var items = new List<LeftoverItemModel>(count);
        for (var i = 0; i < count; i++)
        {
            var t = template[i % template.Count];
            var copy = i / template.Count;
            items.Add(Item($"c-{i + 1:x16}", copy == 0 ? t.DisplayName : $@"{t.DisplayName}\fixture-{copy:D4}", t.GroupName, t.Band,
                t.Category, t.Kind, t.SizeBytes ?? 0, t.Preselected, t.Blockers.FirstOrDefault() ?? ""));
        }
        return items;
    }

    private static LeftoverItemModel Item(string id, string name, string group, Band band, RpcCategory category,
        RpcItemKind kind, ulong bytes, bool preselected = false, string why = "")
    {
        var item = new LeftoverItemModel
        {
            CandidateId = id,
            DisplayName = name,
            GroupName = group,
            Band = band,
            WireBand = band switch
            {
                Band.Safe => RpcBand.Safe,
                Band.Likely => RpcBand.Likely,
                Band.Weak => RpcBand.Weak,
                _ => RpcBand.Blocked,
            },
            Category = category,
            Kind = kind,
            SizeBytes = bytes == 0 ? null : bytes,
            Preselected = preselected,
        };
        if (why.Length > 0) item.Blockers.Add(why);
        return item;
    }
}
