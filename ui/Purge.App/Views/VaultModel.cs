using System.Globalization;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using ProgressDto = Purge.Client.Rpc.Progress;

namespace Purge.App.Views;

/// <summary>The Quarantine vault's states.</summary>
public enum VaultPhase
{
    /// <summary><c>history.index</c> is being read.</summary>
    Loading,
    /// <summary>Nothing is held in quarantine or in a backup.</summary>
    Empty,
    /// <summary>The index could not be read; <see cref="VaultViewModel.Error"/> says why.</summary>
    Error,
    Ready,
}

/// <summary>
/// One cleanup that still holds something (board 16), from its <c>history.index</c> entry: what is held, on which
/// volume, and how long it can still be put back. Plain data (no WinUI types) so the tests can drive it.
/// </summary>
public sealed class VaultBatchModel
{
    /// <summary>Cleanups this close to the end of their file retention are called out.</summary>
    public const int WarnDays = 7;

    public VaultBatchModel(SessionSummary s, DateTimeOffset now)
    {
        Source = s;
        Id = s.Id;
        Name = s.Owner is { DisplayName.Length: > 0 } owner ? owner.DisplayName : s.App;
        Created = HistorySessionModel.FromFileTime(s.Started);
        var local = Created.ToLocalTime();
        When = local.Date == now.LocalDateTime.Date
            ? "Today " + local.ToString("HH:mm", CultureInfo.CurrentCulture)
            : local.ToString("d MMM HH:mm", CultureInfo.CurrentCulture);
        Volume = s.Usage.FirstOrDefault(u => u.Bytes > 0)?.Root ?? s.Usage.FirstOrDefault()?.Root ?? "";
        Bytes = s.BackupBytes;

        var counts = s.Counts ?? new OutcomeCounts();
        Items = counts.Done + counts.PendingReboot;
        FilesPurged = s.Purged.Contains(RetentionClass.Quarantine);
        BackupsPurged = s.Purged.Contains(RetentionClass.Backup);
        FileExpiry = HistorySessionModel.FromFileTime(s.Expires.Quarantine);
        BackupExpiry = HistorySessionModel.FromFileTime(s.Expires.Backups);
        FileDays = FilesPurged ? 0 : DaysLeft(FileExpiry, now);
        BackupDays = BackupsPurged ? 0 : DaysLeft(BackupExpiry, now);

        Partial = s.State == SessionState.PartiallyUndone;
        Expired = !FilesPurged && FileDays == 0 || !BackupsPurged && BackupDays == 0;
        Expiring = !Expired && !FilesPurged && FileDays <= WarnDays;
        Summary = $"{Items.ToString(CultureInfo.CurrentCulture)} {(Items == 1 ? "item" : "items")} · " +
                  $"{LeftoverItemModel.FormatSize(Bytes)}{(Volume.Length > 0 ? " on " + Volume : "")}";
        var parts = new List<string>();
        parts.Add(FilesPurged ? "Files deleted"
            : FileDays > 0 ? $"Files restorable for {FileDays.ToString(CultureInfo.CurrentCulture)} more days"
            : "Files expired · waiting for you to decide");
        parts.Add(BackupsPurged ? "registry backups deleted"
            : $"registry backups {BackupDays.ToString(CultureInfo.CurrentCulture)} days");
        if (s.Undone > 0) parts.Add($"{s.Undone.ToString(CultureInfo.CurrentCulture)} put back");
        Detail = string.Join(" · ", parts);
        State = Expired ? "Expired" : Expiring ? "Expiring" : Partial ? "Partly restored" : "Restorable";
        DaysLeftShown = FilesPurged ? BackupDays : FileDays;
        RingPercent = FilesPurged ? 0 : 100.0 * FileDays / Math.Max(1, (FileExpiry - Created).TotalDays);
    }

    public SessionSummary Source { get; }
    public string Id { get; }
    public string Name { get; }
    public DateTimeOffset Created { get; }
    public string When { get; }
    public string Volume { get; }
    public ulong Bytes { get; }
    public uint Items { get; }
    public bool FilesPurged { get; }
    public bool BackupsPurged { get; }
    public DateTimeOffset FileExpiry { get; }
    public DateTimeOffset BackupExpiry { get; }
    public int FileDays { get; }
    public int BackupDays { get; }
    public bool Partial { get; }
    public bool Expired { get; }
    public bool Expiring { get; }
    public string Summary { get; }
    public string Detail { get; }
    public string State { get; }
    public int DaysLeftShown { get; }
    public double RingPercent { get; }

    /// <summary>
    /// Whether a session's entry still holds something to put back: committed or partly undone, with backup bytes,
    /// and not every class purged. The same rule as the History page's "Undoable".
    /// </summary>
    public static bool Holds(SessionSummary s) =>
        s.State is SessionState.Committed or SessionState.PartiallyUndone && s.BackupBytes > 0
        && !(s.Purged.Contains(RetentionClass.Quarantine) && s.Purged.Contains(RetentionClass.Backup));

    private static int DaysLeft(DateTimeOffset expiry, DateTimeOffset now) =>
        expiry <= now ? 0 : (int)Math.Ceiling((expiry - now).TotalDays);
}

/// <summary>One volume's quarantine use against its real cap (design delta 4), from <c>history.index</c>.</summary>
public sealed class VaultVolumeModel(VolumeCap v, ulong expiringBytes)
{
    public string Root { get; } = v.Root;
    public ulong Used { get; } = v.Used;
    public ulong Cap { get; } = v.Cap;
    public double Percent { get; } = v.Cap > 0 ? Math.Min(100.0, 100.0 * v.Used / v.Cap) : 0;
    public string UsedText { get; } = $"{LeftoverItemModel.FormatSize(v.Used)} of {LeftoverItemModel.FormatSize(v.Cap)} limit";
    public string Note { get; } = expiringBytes > 0
        ? $"Expired or expiring soon: {LeftoverItemModel.FormatSize(expiringBytes)}"
        : "Nothing expiring this week";
}

/// <summary>How the vault's broker launch ended (the view maps <c>BrokerLauncher</c> onto this).</summary>
/// <param name="Broker">The live broker; null when it was not started.</param>
/// <param name="Cancelled">The user said No at the Windows prompt or "Not now" at the explanation.</param>
/// <param name="Message">Why it was not started, for the bar.</param>
public sealed record VaultBrokerLaunch(IVaultBroker? Broker, bool Cancelled, string Message);

/// <summary>
/// The Quarantine vault on real data (design 7a page table): the list and the per-volume use and cap are
/// <c>history.index</c> from the medium engine, so opening the page starts no broker and no prompt. "Put back…"
/// (<c>undo.run</c> for the whole session) and "Review and delete…" (<c>quarantine.expiring</c>, then
/// <c>quarantine.purge</c> with the broker's own dialogs) start the broker on the click. There is no "Empty
/// quarantine" in M3, and expiry only proposes: nothing is deleted without the broker's prompt.
/// <para>
/// Threading as <see cref="HistoryViewModel"/>: driven from the UI thread, it never leaves its context.
/// </para>
/// </summary>
public sealed class VaultViewModel
{
    private const string BusyText = "Another Purge window is changing the quarantine. Wait for it to finish, then try again.";

    private readonly Func<CancellationToken, Task<HistoryIndex>> _readIndex;
    private readonly Func<CancellationToken, Task<VaultBrokerLaunch>> _launch;
    private IVaultBroker? _broker;
    private bool _busy;

    /// <param name="readIndex"><c>history.index</c> on the medium engine.</param>
    /// <param name="launch">Starts the broker (with the first-elevation explanation and the Windows prompt).</param>
    public VaultViewModel(Func<CancellationToken, Task<HistoryIndex>> readIndex,
        Func<CancellationToken, Task<VaultBrokerLaunch>> launch)
    {
        _readIndex = readIndex;
        _launch = launch;
    }

    /// <summary>Raised after every state change, on the thread (synchronization context) that drives the model.</summary>
    public event Action? Changed;

    public VaultPhase Phase { get; private set; } = VaultPhase.Loading;

    /// <summary>Why the index could not be read (<see cref="VaultPhase.Error"/>).</summary>
    public string? Error { get; private set; }

    /// <summary>The cleanups that hold something, newest first.</summary>
    public List<VaultBatchModel> Batches { get; } = [];

    /// <summary>Use and cap per volume.</summary>
    public List<VaultVolumeModel> Volumes { get; } = [];

    /// <summary>Sessions the index lists as interrupted; History offers their recovery.</summary>
    public int Interrupted { get; private set; }

    /// <summary>The held cleanups past a retention date: "Review and delete…" offers them.</summary>
    public IEnumerable<VaultBatchModel> ExpiredBatches => Batches.Where(b => b.Expired);

    /// <summary>The totals line.</summary>
    public string Totals { get; private set; } = "";

    public bool Busy => _busy;

    /// <summary>The waiting line while the broker works or its dialog is open.</summary>
    public string? Waiting { get; private set; }

    /// <summary>The last action's error.</summary>
    public string? ActionError { get; private set; }

    /// <summary>The last action's note (a cancelled prompt, a result).</summary>
    public string? ActionInfo { get; private set; }

    /// <summary>The last action's result title, or null.</summary>
    public string? ResultTitle { get; private set; }

    /// <summary>The Windows prompt was cancelled; the view shows the shell's cancelled bar.</summary>
    public bool PromptCancelled { get; private set; }

    /// <summary>Reads <c>history.index</c>.</summary>
    public async Task LoadAsync(CancellationToken ct = default)
    {
        if (Batches.Count == 0) Phase = VaultPhase.Loading;
        Changed?.Invoke();
        HistoryIndex index;
        try
        {
            index = await _readIndex(ct);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Batches.Clear();
            Volumes.Clear();
            Error = e.Message;
            Phase = VaultPhase.Error;
            Changed?.Invoke();
            return;
        }
        var now = DateTimeOffset.Now;
        Batches.Clear();
        Batches.AddRange(index.Sessions.Where(VaultBatchModel.Holds).Select(s => new VaultBatchModel(s, now))
            .OrderByDescending(b => b.Created));
        Volumes.Clear();
        foreach (var v in index.Volumes)
        {
            var soon = Batches.Where(b => (b.Expired || b.Expiring) && b.Source.Usage.Any(u => u.Serial == v.Serial))
                .Sum(b => (decimal)b.Source.Usage.Where(u => u.Serial == v.Serial).Sum(u => (decimal)u.Bytes));
            Volumes.Add(new VaultVolumeModel(v, (ulong)Math.Min(soon, ulong.MaxValue)));
        }
        Interrupted = index.Sessions.Count(s => s.State == SessionState.Open);
        var bytes = Batches.Aggregate(0UL, (sum, b) => sum + b.Bytes);
        Totals = $"{Batches.Count.ToString(CultureInfo.CurrentCulture)} {(Batches.Count == 1 ? "cleanup holds" : "cleanups hold")} " +
                 $"{LeftoverItemModel.FormatSize(bytes)} · files 30 days, registry backups 180 days";
        Error = null;
        Phase = Batches.Count == 0 ? VaultPhase.Empty : VaultPhase.Ready;
        Changed?.Invoke();
    }

    /// <summary>"Put back…": <c>undo.run</c> for the whole session, through the broker's own dialog.</summary>
    public async Task RestoreAsync(string sessionId, CancellationToken ct = default)
    {
        if (_busy || Batches.FirstOrDefault(b => b.Id == sessionId) is not { } batch) return;
        Begin("Confirm the restore in the Purge security prompt.");
        var changed = false;
        try
        {
            if (await BrokerAsync(ct) is not { } broker) return;
            broker.AllowForeground();
            var progress = new Progress<ProgressDto>(p =>
            {
                Waiting = p.Phase;
                Changed?.Invoke();
            });
            var undo = await broker.UndoAsync(batch.Id, null, progress, ct);
            changed = true;
            ResultTitle = undo.Outcome switch
            {
                Outcome.UndoConflicts => $"{batch.Name} is partly back, with conflicts",
                Outcome.NotClosed => "The session was not recorded completely",
                Outcome.Partial => $"{batch.Name} is partly back",
                _ => $"{batch.Name} is back",
            };
            var lines = undo.Conflicts.Select(c => $"{c.DisplayName}: {c.Conflict.Kind}")
                .Concat(undo.Alerts.Select(ReconcileAlert.Text)).ToList();
            ActionInfo = lines.Count == 0 ? null : string.Join(" ", lines);
        }
        catch (BrokerRpcException e)
        {
            Describe(e, "Nothing was put back: the prompt was cancelled.");
        }
        catch (BrokerLinkException)
        {
            await DropBrokerAsync();
            changed = true;
            ActionError = "The administrator part ended during the restore. Purge cannot tell what was put back; " +
                          "the list is read again.";
        }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
        {
            ActionError = "Couldn't put it back: " + e.Message;
        }
        finally
        {
            End();
        }
        if (changed) await LoadAsync(ct);
    }

    /// <summary>
    /// "Review and delete…": <c>quarantine.expiring</c> says what is past retention now, and <c>quarantine.purge</c>
    /// asks for it in the broker's own dialogs (every item named; user data one item per dialog) before anything is
    /// deleted. Nothing past retention is a note, not a dialog.
    /// </summary>
    public async Task ReviewExpiredAsync(CancellationToken ct = default)
    {
        if (_busy) return;
        Begin("Reading what has expired…");
        var changed = false;
        try
        {
            if (await BrokerAsync(ct) is not { } broker) return;
            var expiring = await broker.ExpiringAsync(ct);
            if (expiring.Items.Count == 0)
            {
                ActionInfo = "Nothing has passed its retention yet; nothing was deleted.";
                return;
            }
            Waiting = "Confirm the delete in the Purge security prompt.";
            Changed?.Invoke();
            broker.AllowForeground();
            var result = await broker.PurgeAsync(expiring.Items.Select(i => i.ExpiryId).ToList(), ct);
            changed = true;
            ResultTitle = result.Purged == 0 ? "Nothing was deleted"
                : $"{result.Purged.ToString(CultureInfo.CurrentCulture)} {(result.Purged == 1 ? "item" : "items")} deleted for good";
            ActionInfo = result.Kept > 0
                ? $"{result.Kept.ToString(CultureInfo.CurrentCulture)} kept: you declined them, or they could not be deleted."
                : null;
        }
        catch (BrokerRpcException e)
        {
            Describe(e, "Nothing was deleted: the prompt was cancelled.");
        }
        catch (BrokerLinkException)
        {
            await DropBrokerAsync();
            changed = true;
            ActionError = "The administrator part ended during the delete. The list is read again.";
        }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
        {
            ActionError = "Couldn't delete the expired items: " + e.Message;
        }
        finally
        {
            End();
        }
        if (changed) await LoadAsync(ct);
    }

    /// <summary>Ends the broker this page started (the page is closing).</summary>
    public async Task CloseAsync() => await DropBrokerAsync();

    private void Describe(BrokerRpcException e, string declined)
    {
        switch (e.Kind)
        {
            case "consent_declined":
                ActionInfo = declined;
                break;
            case "busy":
                ActionError = BusyText;
                break;
            case "needs_recovery":
                ActionError = "An interrupted cleanup comes first. Finish or roll it back from History & undo.";
                break;
            case "store_integrity":
                ActionError = "The quarantine store failed its check. " + e.Message;
                break;
            default:
                ActionError = e.Message;
                break;
        }
    }

    private async Task<IVaultBroker?> BrokerAsync(CancellationToken ct)
    {
        if (_broker is { IsLive: true } live) return live;
        await DropBrokerAsync();
        var launch = await _launch(ct);
        if (launch.Broker is { } broker) return _broker = broker;
        if (launch.Cancelled) PromptCancelled = true;
        else ActionError = launch.Message;
        return null;
    }

    private async Task DropBrokerAsync()
    {
        if (Interlocked.Exchange(ref _broker, null) is { } old)
        {
            try { await old.DisposeAsync(); }
            catch (Exception e) when (e is not OutOfMemoryException) { }
        }
    }

    private void Begin(string waiting)
    {
        _busy = true;
        Waiting = waiting;
        ActionError = null;
        ActionInfo = null;
        ResultTitle = null;
        PromptCancelled = false;
        Changed?.Invoke();
    }

    private void End()
    {
        _busy = false;
        Waiting = null;
        Changed?.Invoke();
    }
}
