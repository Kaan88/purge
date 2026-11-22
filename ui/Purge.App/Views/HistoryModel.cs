using System.Globalization;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using ProgressDto = Purge.Client.Rpc.Progress;
using RpcItemKind = Purge.Client.Rpc.ItemKind;

namespace Purge.App.Views;

/// <summary>The History page's states (design 6.3 page table, "History &amp; undo").</summary>
public enum HistoryPhase
{
    /// <summary><c>history.index</c> is being read.</summary>
    Loading,
    /// <summary>The index has no session.</summary>
    Empty,
    /// <summary>The index could not be read; <see cref="HistoryViewModel.Error"/> says why.</summary>
    Error,
    Ready,
}

/// <summary>The chip a session shows; each has its own glyph in the view, so the state never rests on colour.</summary>
public enum HistoryChip { Undoable, Caution, Neutral }

/// <summary>
/// One session of <c>history.index</c> as the page lists it: time, app, count, size, days left, state. Plain data (no
/// WinUI types) so the view-model tests can drive it without the app.
/// </summary>
public sealed class HistorySessionModel
{
    /// <summary>
    /// A session <c>journal.pending</c> found interrupted that the index does not list as open (an <c>Unindexed</c>
    /// one, or a run that never reached its index entry): listed from the journal's facts, with recovery offered.
    /// </summary>
    public HistorySessionModel(PendingSession p, DateTimeOffset now)
        : this(new SessionSummary
        {
            Id = p.Session,
            App = p.App,
            Started = p.Started,
            State = SessionState.Open,
            Counts = new OutcomeCounts { Done = p.Done },
            Expires = new Expiry(),
        }, now)
    {
        FromJournal = true;
        Detail = $"{p.Done.ToString(CultureInfo.CurrentCulture)} of {p.Total.ToString(CultureInfo.CurrentCulture)} items done · " +
                 "found in the journals";
    }

    public HistorySessionModel(SessionSummary s, DateTimeOffset now)
    {
        Source = s;
        Id = s.Id;
        Name = s.Owner is { DisplayName.Length: > 0 } owner ? owner.DisplayName : s.App;
        Started = FromFileTime(s.Started);
        var local = Started.ToLocalTime();
        Time = local.ToString("HH:mm", CultureInfo.CurrentCulture);
        Day = local.Date;

        var counts = s.Counts ?? new OutcomeCounts();
        var parts = new List<string> { Count(counts.Done, "item moved", "items moved") };
        if (s.BackupBytes > 0) parts.Add(LeftoverItemModel.FormatSize(s.BackupBytes));
        if (counts.HeldRetry > 0) parts.Add($"{counts.HeldRetry.ToString(CultureInfo.CurrentCulture)} held, in use");
        if (counts.PendingReboot > 0) parts.Add($"{counts.PendingReboot.ToString(CultureInfo.CurrentCulture)} at the next restart");
        if (counts.Failed > 0) parts.Add($"{counts.Failed.ToString(CultureInfo.CurrentCulture)} failed");
        if (s.Undone > 0) parts.Add($"{s.Undone.ToString(CultureInfo.CurrentCulture)} put back");
        Detail = string.Join(" · ", parts);

        FileExpiry = FromFileTime(s.Expires.Quarantine);
        BackupExpiry = FromFileTime(s.Expires.Backups);
        FileDays = DaysLeft(FileExpiry, now);
        BackupDays = DaysLeft(BackupExpiry, now);
        var purgedAll = s.Purged.Contains(RetentionClass.Quarantine) && s.Purged.Contains(RetentionClass.Backup);
        Held = s.State is SessionState.Committed or SessionState.PartiallyUndone && s.BackupBytes > 0 && !purgedAll;
        Interrupted = s.State == SessionState.Open;

        (State, Chip) = s.State switch
        {
            SessionState.Open => ("Interrupted", HistoryChip.Caution),
            SessionState.PartiallyUndone => ("Partly restored", HistoryChip.Caution),
            SessionState.Undone => ("Restored", HistoryChip.Neutral),
            SessionState.Aborted => ("Rolled back", HistoryChip.Neutral),
            _ when !Held => ("Nothing to restore", HistoryChip.Neutral),
            _ => ("Undoable", HistoryChip.Undoable),
        };
    }

    public SessionSummary Source { get; }
    public string Id { get; }
    public string Name { get; }
    public DateTimeOffset Started { get; }
    public DateTime Day { get; }
    public string Time { get; }
    public string Detail { get; }

    /// <summary>Listed from <c>journal.pending</c> (broker), not from the index.</summary>
    public bool FromJournal { get; }
    public string State { get; private set; }
    public HistoryChip Chip { get; private set; }
    public DateTimeOffset FileExpiry { get; }
    public DateTimeOffset BackupExpiry { get; }
    public int FileDays { get; }
    public int BackupDays { get; }

    /// <summary>Something is still in quarantine or in a backup to put back.</summary>
    public bool Held { get; }

    /// <summary>
    /// The session was not recorded completely (<c>Open</c> in the index, or listed by <c>journal.pending</c>);
    /// recovery comes first.
    /// </summary>
    public bool Interrupted { get; private set; }

    /// <summary><c>journal.pending</c> lists a session the index shows as finished (its report was never written).</summary>
    internal void MarkInterrupted()
    {
        Interrupted = true;
        State = "Interrupted";
        Chip = HistoryChip.Caution;
    }

    /// <summary>A reconcile alert was found among the items read with "Show items" (review M3-R2 S5).</summary>
    public bool HasAlert { get; set; }

    /// <summary>The timeline marker's second line.</summary>
    public string Restorable => !Held ? "Nothing to restore"
        : FileDays > 0 ? $"Files {FileDays} d · registry {BackupDays} d" : $"Files expired · registry {BackupDays} d";

    /// <summary>The detail pane's expiry line.</summary>
    public string Expiry => Interrupted ? "The session was not recorded completely."
        : !Held ? State
        : $"Files restorable until {FileExpiry.ToLocalTime().ToString("d MMM yyyy", CultureInfo.CurrentCulture)} ({FileDays} days), " +
          $"registry and task backups until {BackupExpiry.ToLocalTime().ToString("d MMM yyyy", CultureInfo.CurrentCulture)}";

    internal static DateTimeOffset FromFileTime(ulong fileTime) =>
        fileTime is 0 or > long.MaxValue ? DateTimeOffset.MinValue : DateTimeOffset.FromFileTime((long)fileTime);

    private static int DaysLeft(DateTimeOffset expiry, DateTimeOffset now) =>
        expiry <= now ? 0 : (int)Math.Ceiling((expiry - now).TotalDays);

    private static string Count(uint n, string one, string many) =>
        $"{n.ToString(CultureInfo.CurrentCulture)} {(n == 1 ? one : many)}";
}

/// <summary>One item of <c>history.get</c>, with its reconcile alert when there is one.</summary>
public sealed class HistoryEntryModel(HistoryItem item)
{
    public HistoryItem Source { get; } = item;
    public uint Op { get; } = item.Op;
    public string DisplayName { get; } = item.DisplayName;

    public string KindText { get; } = item.Kind switch
    {
        RpcItemKind.Folder => "Folder",
        RpcItemKind.RegistryKey => "Registry key",
        RpcItemKind.RegistryValue => "Registry value",
        RpcItemKind.RegistryData => "Registry data",
        RpcItemKind.Service => "Service",
        RpcItemKind.Task => "Task",
        RpcItemKind.FirewallRule => "Firewall rule",
        RpcItemKind.Package => "Package",
        _ => "File",
    };

    public string OutcomeText { get; } = item.Undone ? "Put back" : item.Outcome.Kind switch
    {
        "Done" => "Moved to quarantine",
        "Vanished" => "Already gone",
        "Skipped" => "Skipped",
        "HeldRetry" => "Held, in use",
        "PendingReboot" => "Moved at the next restart",
        "PendingDelete" => "Removed at the next restart",
        "Failed" => "Failed",
        _ => item.Outcome.Kind,
    };

    /// <summary>The S5 mark: what reconcile found in quarantine in this item's place, or null.</summary>
    public string? AlertText { get; } = item.Alert is { } alert ? ReconcileAlert.Text(alert) : null;

    public bool HasAlert => AlertText is not null;

    /// <summary>Only an item that changed something and is not back yet can be ticked for "Restore selected".</summary>
    public bool Selectable { get; } = !item.Undone && item.Outcome.Kind is "Done" or "PendingReboot";

    public bool Checked { get; set; }
}

/// <summary>How the History page's broker launch ended (the view maps <c>BrokerLauncher</c> onto this).</summary>
/// <param name="Broker">The live broker; null when it was not started.</param>
/// <param name="Cancelled">The user said No at the Windows prompt or "Not now" at the explanation.</param>
/// <param name="Message">Why it was not started, for the bar.</param>
public sealed record HistoryBrokerLaunch(IHistoryBroker? Broker, bool Cancelled, string Message);

/// <summary>
/// The History page's view model. The list is <c>history.index</c> from the medium engine, so opening the page never
/// starts the broker or a UAC prompt; "Show items" (<c>history.get</c>), Restore (<c>undo.run</c>) and "Check for
/// interrupted cleanups" (<c>journal.pending</c>) start it on the click (design 6.3). Reconcile alerts (review M3-R2
/// S5) show per item and in the restore result.
/// <para>
/// Threading: the model is driven from the UI thread and never leaves its context (no <c>ConfigureAwait(false)</c>),
/// so every state change and every <see cref="Changed"/> happens on the thread that drives it, and the view's render
/// never reads a list while a pool thread rewrites it. The view still posts its render through its
/// <c>DispatcherQueue</c>, as the Programs page does.
/// </para>
/// </summary>
public sealed class HistoryViewModel
{
    private const string BusyText = "Another Purge window is changing the quarantine. Wait for it to finish, then try again.";

    private const string PendingBusyText =
        "Another Purge window is working on the quarantine. Try again when it has finished; nothing is listed until then.";

    private readonly Func<CancellationToken, Task<HistoryIndex>> _readIndex;
    private readonly Func<CancellationToken, Task<HistoryBrokerLaunch>> _launch;
    private readonly Dictionary<string, PendingSession> _pending = new(StringComparer.Ordinal);
    private IHistoryBroker? _broker;
    private bool _busy;
    private string? _selectAfterLoad;

    /// <param name="readIndex"><c>history.index</c> on the medium engine.</param>
    /// <param name="launch">Starts the broker (with the first-elevation explanation and the Windows prompt).</param>
    public HistoryViewModel(Func<CancellationToken, Task<HistoryIndex>> readIndex,
        Func<CancellationToken, Task<HistoryBrokerLaunch>> launch)
    {
        _readIndex = readIndex;
        _launch = launch;
    }

    /// <summary>Raised after every state change, on the thread (synchronization context) that drives the model.</summary>
    public event Action? Changed;

    public HistoryPhase Phase { get; private set; } = HistoryPhase.Loading;

    /// <summary>Why the index could not be read (<see cref="HistoryPhase.Error"/>).</summary>
    public string? Error { get; private set; }

    /// <summary>Newest first.</summary>
    public List<HistorySessionModel> Sessions { get; } = [];

    public HistorySessionModel? Selected { get; private set; }

    /// <summary>The items of <see cref="Selected"/> once "Show items" has read them; null before.</summary>
    public List<HistoryEntryModel>? Items { get; private set; }

    /// <summary>A broker call is running or its dialog is open.</summary>
    public bool Busy => _busy;

    /// <summary>The waiting line while the broker works or its dialog is open.</summary>
    public string? Waiting { get; private set; }

    /// <summary>The waiting bar's second line.</summary>
    public string WaitingDetail { get; private set; } = "";

    /// <summary>The last action's error for the detail bar.</summary>
    public string? ActionError { get; private set; }

    /// <summary>The last action's note (a cancelled dialog, a restore's result).</summary>
    public string? ActionInfo { get; private set; }

    /// <summary>The Windows prompt was cancelled; the view shows the cancelled bar.</summary>
    public bool PromptCancelled { get; private set; }

    /// <summary>The last restore's outcome title, or null.</summary>
    public string? RestoreTitle { get; private set; }

    /// <summary>The last restore's conflict and alert lines.</summary>
    public List<string> RestoreLines { get; } = [];

    public bool CanRestore => !_busy && Selected is { Held: true };

    public int CheckedCount => Items?.Count(i => i.Checked && i.Selectable) ?? 0;

    /// <summary>Reads <c>history.index</c>; keeps the selection when the session is still listed.</summary>
    public async Task LoadAsync(CancellationToken ct = default)
    {
        var keep = Selected?.Id;
        if (Sessions.Count == 0) Phase = HistoryPhase.Loading;
        Changed?.Invoke();
        HistoryIndex index;
        try
        {
            index = await _readIndex(ct);
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Sessions.Clear();
            Selected = null;
            Items = null;
            Error = e.Message;
            Phase = HistoryPhase.Error;
            Changed?.Invoke();
            return;
        }
        var now = DateTimeOffset.Now;
        var alerts = Sessions.Where(s => s.HasAlert).Select(s => s.Id).ToHashSet(StringComparer.Ordinal);
        Sessions.Clear();
        var listed = index.Sessions.Select(s => new HistorySessionModel(s, now)).ToList();
        // What the journal.pending just read found is interrupted whatever the index says, and is listed from the
        // journal when the index has no entry for it.
        foreach (var s in listed.Where(s => _pending.ContainsKey(s.Id))) s.MarkInterrupted();
        var ids = listed.Select(s => s.Id).ToHashSet(StringComparer.Ordinal);
        listed.AddRange(_pending.Values.Where(p => !ids.Contains(p.Session)).Select(p => new HistorySessionModel(p, now)));
        Sessions.AddRange(listed.OrderByDescending(s => s.Started));
        foreach (var s in Sessions) s.HasAlert = alerts.Contains(s.Id);
        // A journal.pending answer is shown once: the next refresh drops its marks, so a session that ended
        // since (its run committed, or it was recovered) is never left marked Interrupted. Asking again
        // brings back what is still pending.
        _pending.Clear();
        Error = null;
        Phase = Sessions.Count == 0 ? HistoryPhase.Empty : HistoryPhase.Ready;
        if (_selectAfterLoad is { } jump) keep = jump;
        _selectAfterLoad = null;
        var next = Sessions.FirstOrDefault(s => s.Id == keep) ?? Sessions.FirstOrDefault();
        if (next?.Id != Selected?.Id || next is null) Items = null;
        Selected = next;
        Changed?.Invoke();
    }

    public void Select(string sessionId)
    {
        if (Sessions.FirstOrDefault(s => s.Id == sessionId) is not { } session || session == Selected) return;
        Selected = session;
        Items = null;
        ActionError = null;
        ActionInfo = null;
        RestoreTitle = null;
        RestoreLines.Clear();
        PromptCancelled = false;
        Changed?.Invoke();
    }

    /// <summary>"Show items": <c>history.get</c> through the broker, which starts on this click.</summary>
    public Task ShowItemsAsync(CancellationToken ct = default) => ReadItemsAsync(clear: true, ct);

    private async Task ReadItemsAsync(bool clear, CancellationToken ct)
    {
        if (_busy || Selected is not { } session) return;
        Begin("Reading the items of this cleanup…", "", clear);
        try
        {
            if (await BrokerAsync(ct) is not { } broker) return;
            var detail = await broker.GetAsync(session.Id, ct);
            if (Selected != session) return;
            Items = detail.Items.Select(i => new HistoryEntryModel(i)).ToList();
            session.HasAlert = Items.Any(i => i.HasAlert);
        }
        catch (BrokerRpcException e) when (e.Kind == "gone")
        {
            ActionError = "This cleanup is no longer in Purge's store.";
        }
        catch (BrokerLinkException)
        {
            await DropBrokerAsync();
            ActionError = "The administrator part ended before it answered. Try again.";
        }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
        {
            ActionError = "Couldn't read the items: " + e.Message;
        }
        finally
        {
            End();
        }
    }

    /// <summary>Restore: <c>undo.run</c> for the ticked items (<paramref name="all"/> false) or the whole session.</summary>
    public async Task RestoreAsync(bool all, CancellationToken ct = default)
    {
        if (!CanRestore || Selected is not { } session) return;
        List<uint>? ops = null;
        if (!all)
        {
            ops = Items?.Where(i => i.Checked && i.Selectable).Select(i => i.Op).ToList();
            if (ops is not { Count: > 0 }) return;
        }
        Begin("Confirm the restore in the Purge security prompt.", "Nothing has been put back yet.");
        RestoreTitle = null;
        RestoreLines.Clear();
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
            var undo = await broker.UndoAsync(session.Id, ops, progress, ct);
            changed = true;
            foreach (var conflict in undo.Conflicts)
                RestoreLines.Add($"{conflict.DisplayName}: {conflict.Conflict.Kind}");
            foreach (var alert in undo.Alerts)
                RestoreLines.Add(ReconcileAlert.Text(alert));
            RestoreTitle = undo.Outcome switch
            {
                Outcome.UndoConflicts => "Put back, with conflicts",
                Outcome.NotClosed => "The session was not recorded completely",
                Outcome.Partial => "Partly put back",
                _ => "Put back",
            };
            ActionInfo = undo.Conflicts.Count == 0
                ? "What you chose is back where it was."
                : $"{undo.Conflicts.Count.ToString(CultureInfo.CurrentCulture)} items could not be put back; they are listed below.";
            if (undo.Alerts.Count > 0) session.HasAlert = true;
        }
        catch (BrokerRpcException e) when (e.Kind == "consent_declined")
        {
            ActionInfo = "Nothing was put back: the prompt was cancelled.";
        }
        catch (BrokerRpcException e) when (e.Kind == "needs_recovery")
        {
            ActionError = "An interrupted cleanup comes first. Finish or roll it back, then restore.";
            // The broker is up already: list the interrupted sessions now, without another prompt.
            changed = await ReadPendingAsync(ct);
        }
        catch (BrokerRpcException e) when (e.Kind == "busy")
        {
            ActionError = BusyText;
        }
        catch (BrokerLinkException)
        {
            await DropBrokerAsync();
            changed = true;
            ActionError = "The administrator part ended during the restore. Purge cannot tell what was put back; " +
                          "the list below is read again.";
        }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
        {
            ActionError = "Couldn't put it back: " + e.Message;
        }
        finally
        {
            End();
        }
        if (!changed) return;
        var hadItems = Items is not null;
        await LoadAsync(ct);
        if (hadItems && Selected?.Id == session.Id && _broker is { IsLive: true }) await ReadItemsAsync(clear: false, ct);
    }

    /// <summary>
    /// The recovery banner of an interrupted session: <c>journal.resume</c> (<paramref name="rollback"/> false) or
    /// <c>journal.rollback</c>, each through the broker's own dialog.
    /// </summary>
    public async Task RecoverAsync(bool rollback, CancellationToken ct = default)
    {
        if (_busy || Selected is not { Interrupted: true } session) return;
        Begin(rollback ? "Confirm the roll back in the Purge security prompt." : "Confirm the resume in the Purge security prompt.",
            "Nothing has been changed yet.");
        RestoreTitle = null;
        RestoreLines.Clear();
        var changed = false;
        try
        {
            if (await BrokerAsync(ct) is not { } broker) return;
            broker.AllowForeground();
            var result = await broker.RecoverAsync(session.Id, rollback, ct);
            changed = true;
            _pending.Remove(session.Id);
            foreach (var alert in result.Alerts)
                RestoreLines.Add(ReconcileAlert.Text(alert));
            RestoreTitle = result.Outcome switch
            {
                Outcome.Complete => rollback ? "Rolled back" : "Finished",
                Outcome.NotClosed => "The session was not recorded completely",
                _ => rollback ? "Partly rolled back" : "Partly finished",
            };
            ActionInfo = result.Outcome == Outcome.Complete ? null : "Some items are still held or failed; the list below says which.";
            if (result.Alerts.Count > 0) session.HasAlert = true;
        }
        catch (BrokerRpcException e) when (e.Kind == "consent_declined")
        {
            ActionInfo = "Nothing was changed: the prompt was cancelled.";
        }
        catch (BrokerRpcException e) when (e.Kind == "busy")
        {
            ActionError = BusyText;
        }
        catch (BrokerLinkException)
        {
            await DropBrokerAsync();
            changed = true;
            ActionError = "The administrator part ended during the recovery. The list below is read again.";
        }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
        {
            ActionError = "Couldn't recover the session: " + e.Message;
        }
        finally
        {
            End();
        }
        if (changed) await LoadAsync(ct);
    }

    /// <summary>
    /// "Check for interrupted cleanups": <c>journal.pending</c> through the broker, which starts on this click, never on
    /// page open (design 6.3). The index gets a run's entry only when the run ends, so a run cut short before that, and
    /// one whose report or entry was never written (<c>Unindexed</c>), are found only here; each is then listed with
    /// Resume and Roll back.
    /// </summary>
    public async Task CheckInterruptedAsync(CancellationToken ct = default)
    {
        if (_busy) return;
        Begin("Looking for interrupted cleanups…", "");
        var read = false;
        try
        {
            if (await BrokerAsync(ct) is null) return;
            read = await ReadPendingAsync(ct);
            if (read && _pending.Count == 0) ActionInfo = "No cleanup was interrupted.";
        }
        finally
        {
            End();
        }
        if (read) await LoadAsync(ct);
    }

    /// <summary>Reads <c>journal.pending</c> on the live broker into the pending set; false when it could not.</summary>
    private async Task<bool> ReadPendingAsync(CancellationToken ct)
    {
        if (_broker is not { IsLive: true } broker) return false;
        try
        {
            var list = await broker.PendingAsync(ct);
            _pending.Clear();
            foreach (var p in list.Sessions) _pending[p.Session] = p;
            // Show the first one found unless an interrupted session is selected already.
            if (Selected is not { Interrupted: true } && list.Sessions.Count > 0) _selectAfterLoad = list.Sessions[0].Session;
            return true;
        }
        catch (BrokerRpcException e) when (e.Kind == "busy")
        {
            // Another broker is changing the store: its live run would read as interrupted, so the broker does
            // not list anything until it has finished.
            _pending.Clear();
            ActionError = PendingBusyText;
        }
        catch (BrokerLinkException)
        {
            await DropBrokerAsync();
            ActionError = "The administrator part ended before it answered. Try again.";
        }
        catch (Exception e) when (e is not OutOfMemoryException and not OperationCanceledException)
        {
            ActionError = "Couldn't look for interrupted cleanups: " + e.Message;
        }
        return false;
    }

    /// <summary>Ends the broker this page started (the page is closing).</summary>
    public async Task CloseAsync() => await DropBrokerAsync();

    private async Task<IHistoryBroker?> BrokerAsync(CancellationToken ct)
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

    private void Begin(string waiting, string detail, bool clear = true)
    {
        _busy = true;
        Waiting = waiting;
        WaitingDetail = detail;
        if (clear)
        {
            ActionError = null;
            ActionInfo = null;
            RestoreTitle = null;
            RestoreLines.Clear();
        }
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
