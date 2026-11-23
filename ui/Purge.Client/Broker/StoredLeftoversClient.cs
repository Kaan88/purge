using System.Text.Json;
using Purge.Client.Rpc;

namespace Purge.Client.Broker;

/// <summary>
/// The broker side of "Check for leftovers" on a program removed outside Purge (design 7a delta 5): whether Purge
/// stored its fingerprint (<c>leftovers.stored</c>), then a scan from that fingerprint (<c>leftovers.scan
/// {program_id}</c>). The interface exists so the Programs page's controller can be tested without a pipe.
/// </summary>
public interface IStoredLeftoversBroker : IAsyncDisposable
{
    /// <summary><c>leftovers.stored {program_ids}</c>: the ids among them with a stored fingerprint.</summary>
    Task<IReadOnlyList<string>> StoredAsync(IReadOnlyList<string> programIds, CancellationToken ct);

    /// <summary><c>leftovers.scan {program_id}</c>: a scan from the stored fingerprint; <c>gone</c> when there is none.</summary>
    Task<ScanResult> ScanStoredAsync(string programId, Action<Progress>? progress, CancellationToken ct);

    /// <summary>
    /// Hands the live link to the Leftovers page: this wrapper no longer closes it. Null on a second call (and from a
    /// test's broker, which has no session).
    /// </summary>
    BrokerSession? TakeSession();
}

/// <summary>
/// <see cref="IStoredLeftoversBroker"/> over a launched broker, whose <c>engine.hello</c> was answered when the
/// session was made (<see cref="BrokerSession"/>); <c>scan.progress</c> feeds the scan in flight only.
/// </summary>
public sealed class StoredLeftoversClient : IStoredLeftoversBroker
{
    private readonly BrokerSession _session;
    private readonly object _progressGate = new();
    private Action<Progress>? _progress;
    private int _handedOver;
    private int _disposed;

    /// <summary>Over a launched broker; disposing this ends it unless the session was handed over.</summary>
    public StoredLeftoversClient(BrokerSession session)
    {
        _session = session;
        _session.Rpc.Notification += OnNotification;
    }

    public async Task<IReadOnlyList<string>> StoredAsync(IReadOnlyList<string> programIds, CancellationToken ct)
    {
        var result = await _session.Rpc.CallAsync("leftovers.stored", new ProgramsParams { ProgramIds = [.. programIds] },
            RpcJsonContext.Default.ProgramsParams, RpcJsonContext.Default.StoredResult, ct).ConfigureAwait(false);
        return result.Stored;
    }

    public async Task<ScanResult> ScanStoredAsync(string programId, Action<Progress>? progress, CancellationToken ct)
    {
        lock (_progressGate) _progress = progress;
        try
        {
            return await _session.Rpc.CallAsync("leftovers.scan", new LeftoversScanParams { ProgramId = programId },
                RpcJsonContext.Default.LeftoversScanParams, RpcJsonContext.Default.ScanResult, ct).ConfigureAwait(false);
        }
        finally
        {
            lock (_progressGate) _progress = null;
        }
    }

    public BrokerSession? TakeSession()
    {
        if (Interlocked.Exchange(ref _handedOver, 1) != 0) return null;
        _session.Rpc.Notification -= OnNotification;
        return _session;
    }

    private void OnNotification(BrokerNotification notification)
    {
        if (notification.Method != "scan.progress") return;
        Progress? progress;
        try { progress = notification.Params.Deserialize(RpcJsonContext.Default.Progress); }
        catch (Exception e) when (e is JsonException or InvalidOperationException) { return; }
        if (progress is null) return;
        Action<Progress>? handler;
        lock (_progressGate) handler = _progress;
        try { handler?.Invoke(progress); }
        catch (Exception e) when (e is not OutOfMemoryException) { }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _session.Rpc.Notification -= OnNotification;
        // A session handed to the leftovers page belongs to that page now.
        if (Volatile.Read(ref _handedOver) == 0)
            await _session.DisposeAsync().ConfigureAwait(false);
    }
}
