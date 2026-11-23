using System.Text.Json;
using Purge.Client.Rpc;

namespace Purge.Client.Broker;

/// <summary>
/// The broker calls of the History page (design 6.3): <c>history.get</c> for "Show items" and <c>undo.run</c> for
/// Restore. The list itself is <c>history.index</c> on the medium engine; only these two start the broker. The
/// interface exists so the page's view model can be tested without a pipe.
/// </summary>
public interface IHistoryBroker : IAsyncDisposable
{
    /// <summary>False once the broker link ended; the page then launches a new broker on the next click.</summary>
    bool IsLive { get; }

    /// <summary>Lets the broker's consent dialog come to the foreground; called before <c>undo.run</c>.</summary>
    void AllowForeground();

    /// <summary><c>history.get {session}</c>: the session's items, how each ended, and the reconcile alerts.</summary>
    Task<HistoryDetail> GetAsync(string session, CancellationToken ct);

    /// <summary><c>undo.run {session, item_ids?}</c>: the broker's dialog, then the put-back. Null ops: everything.</summary>
    Task<UndoResult> UndoAsync(string session, IReadOnlyList<uint>? ops, IProgress<Progress>? progress, CancellationToken ct);

    /// <summary><c>journal.resume</c> or <c>journal.rollback {session}</c>: the recovery banner's two buttons.</summary>
    Task<OutcomeResult> RecoverAsync(string session, bool rollback, CancellationToken ct);

    /// <summary>
    /// <c>journal.pending</c>: the interrupted sessions the broker reads from the journals, those the index does not
    /// list as open among them (a run that never reached its index entry, or whose report was never written).
    /// </summary>
    Task<PendingList> PendingAsync(CancellationToken ct);
}

/// <summary>
/// The broker calls of the Quarantine vault (design 7a page table): <c>undo.run</c> for "Put back…" and
/// <c>quarantine.expiring</c> then <c>quarantine.purge</c> for "Review and delete…" and for "Delete now" (the same
/// two calls, with the items that are not past their retention listed too). The list is
/// <c>history.index</c> on the medium engine; only these start the broker.
/// </summary>
public interface IVaultBroker : IAsyncDisposable
{
    /// <summary>False once the broker link ended; the page then launches a new broker on the next click.</summary>
    bool IsLive { get; }

    /// <summary>Lets the broker's dialog come to the foreground; called before a call that shows one.</summary>
    void AllowForeground();

    /// <summary><c>undo.run {session}</c> for the whole session.</summary>
    Task<UndoResult> UndoAsync(string session, IReadOnlyList<uint>? ops, IProgress<Progress>? progress, CancellationToken ct);

    /// <summary>
    /// <c>quarantine.expiring {include_not_due}</c>: what is past its retention now, with the broker's ids; with
    /// <paramref name="includeNotDue"/> also the quarantined items that are not (<see cref="ExpiringItem.Due"/> false).
    /// </summary>
    Task<ExpiringList> ExpiringAsync(bool includeNotDue, CancellationToken ct);

    /// <summary>
    /// <c>quarantine.purge {expiry_ids}</c>: the broker's purge dialogs, then the deletes the user approved. The ids
    /// are all the request says; the broker itself tells an expired entry from one deleted before its retention ends
    /// and asks for the latter in its "Delete now" dialog.
    /// </summary>
    Task<PurgeResult> PurgeAsync(IReadOnlyList<string> expiryIds, CancellationToken ct);
}

/// <summary>
/// <see cref="IHistoryBroker"/> and <see cref="IVaultBroker"/> over a launched broker; disposing it ends the broker. The
/// session's <c>engine.hello</c> was answered when it was made (<see cref="BrokerSession"/>), so these calls go straight out.
/// </summary>
public sealed class HistoryBroker : IHistoryBroker, IVaultBroker
{
    private readonly BrokerSession _session;
    private IProgress<Progress>? _progress;

    public HistoryBroker(BrokerSession session)
    {
        _session = session;
        _session.Rpc.Notification += OnNotification;
    }

    public bool IsLive => _session.Rpc.IsLive;

    public void AllowForeground() => _session.AllowForeground();

    public Task<HistoryDetail> GetAsync(string session, CancellationToken ct) =>
        _session.Rpc.CallAsync("history.get", new SessionParams { Session = session }, RpcJsonContext.Default.SessionParams,
            RpcJsonContext.Default.HistoryDetail, ct);

    public async Task<UndoResult> UndoAsync(string session, IReadOnlyList<uint>? ops, IProgress<Progress>? progress,
        CancellationToken ct)
    {
        var parameters = new UndoParams { Session = session, ItemIds = ops is null ? null : [.. ops] };
        _progress = progress;
        try
        {
            return await _session.Rpc.CallAsync("undo.run", parameters, RpcJsonContext.Default.UndoParams,
                RpcJsonContext.Default.UndoResult, ct).ConfigureAwait(false);
        }
        finally
        {
            _progress = null;
        }
    }

    public Task<OutcomeResult> RecoverAsync(string session, bool rollback, CancellationToken ct) =>
        _session.Rpc.CallAsync(rollback ? "journal.rollback" : "journal.resume", new SessionParams { Session = session },
            RpcJsonContext.Default.SessionParams, RpcJsonContext.Default.OutcomeResult, ct);

    public Task<PendingList> PendingAsync(CancellationToken ct) =>
        _session.Rpc.CallAsync("journal.pending", RpcJsonContext.Default.PendingList, ct);

    public Task<ExpiringList> ExpiringAsync(bool includeNotDue, CancellationToken ct) =>
        _session.Rpc.CallAsync("quarantine.expiring", new ExpiringParams { IncludeNotDue = includeNotDue },
            RpcJsonContext.Default.ExpiringParams, RpcJsonContext.Default.ExpiringList, ct);

    public Task<PurgeResult> PurgeAsync(IReadOnlyList<string> expiryIds, CancellationToken ct) =>
        _session.Rpc.CallAsync("quarantine.purge", new PurgeParams { ExpiryIds = [.. expiryIds] },
            RpcJsonContext.Default.PurgeParams, RpcJsonContext.Default.PurgeResult, ct);

    public ValueTask DisposeAsync()
    {
        _session.Rpc.Notification -= OnNotification;
        return _session.DisposeAsync();
    }

    private void OnNotification(BrokerNotification notification)
    {
        if (notification.Method != "undo.progress" || _progress is not { } progress) return;
        if (notification.Params.ValueKind is JsonValueKind.Object
            && notification.Params.Deserialize(RpcJsonContext.Default.Progress) is { } p)
            progress.Report(p);
    }
}
