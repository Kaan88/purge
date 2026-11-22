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
}

/// <summary><see cref="IHistoryBroker"/> over a launched broker; disposing it ends the broker.</summary>
public sealed class HistoryBroker : IHistoryBroker
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
