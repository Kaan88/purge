using System.Text.Json;
using Purge.Client.Rpc;

namespace Purge.Client.Broker;

/// <summary>
/// The broker calls the Leftovers page makes (design 6.3): the scan, its pages of candidates,
/// <c>candidate.explain</c>, <c>plan.create</c>, <c>plan.execute</c> and the two result actions.
/// The interface exists so the page's view model can be tested without a pipe.
/// </summary>
public interface ILeftoversBroker
{
    /// <summary>The broker's consent dialog is up (<c>consent.shown</c>); the code is the one in its footer.</summary>
    event Action<ConsentShown>? ConsentShown;

    /// <summary><c>baseline.changed</c>, including the scans the broker offers again after a build.</summary>
    event Action<BaselineChanged>? BaselineChanged;

    /// <summary>False once the broker link ended; the page then cannot rescan or retry.</summary>
    bool IsLive { get; }

    /// <summary><c>leftovers.scan {session_id, forced?}</c> after an uninstall.</summary>
    Task<ScanResult> ScanSessionAsync(string sessionId, bool forced, IProgress<Progress>? progress, CancellationToken ct);

    /// <summary><c>leftovers.scan {program_id}</c> from a stored fingerprint.</summary>
    Task<ScanResult> ScanStoredAsync(string programId, IProgress<Progress>? progress, CancellationToken ct);

    /// <summary>One page of <c>scan.candidates</c>; the broker's limit is 500.</summary>
    Task<CandidatesPage> CandidatesAsync(string scanId, uint offset, int limit, CancellationToken ct);

    /// <summary><c>candidate.explain</c>: the evidence and blocker lines of one candidate.</summary>
    Task<Explanation> ExplainAsync(string scanId, string candidateId, CancellationToken ct);

    /// <summary><c>plan.create {scan_id, selected[]}</c>; a refused plan is a <c>plan_refused</c> error.</summary>
    Task<PlanCreated> CreatePlanAsync(string scanId, IReadOnlyList<string> selected, CancellationToken ct);

    /// <summary><c>plan.execute {plan_id, restore_point}</c>: shows the broker's dialog, then runs the plan.</summary>
    Task<ExecResult> ExecuteAsync(string planId, RestorePoint restorePoint, IProgress<Progress>? progress, CancellationToken ct);

    /// <summary><c>undo.run {session}</c>: restores everything one session moved.</summary>
    Task<UndoResult> UndoAsync(string session, IProgress<Progress>? progress, CancellationToken ct);

    /// <summary><c>journal.retry_held {session}</c>: tries the items a run left in place again.</summary>
    Task<OutcomeResult> RetryHeldAsync(string session, CancellationToken ct);
}

/// <summary>
/// <see cref="ILeftoversBroker"/> over the broker pipe. Notifications are read off the shared
/// <see cref="BrokerRpcClient.Notification"/> event; progress notifications are forwarded to the
/// <see cref="IProgress{T}"/> of the call in flight (one request at a time is the broker's rule).
/// </summary>
public sealed class LeftoversBroker : ILeftoversBroker
{
    private readonly BrokerRpcClient _rpc;
    private IProgress<Progress>? _progress;

    public LeftoversBroker(BrokerRpcClient rpc)
    {
        _rpc = rpc;
        _rpc.Notification += OnNotification;
    }

    public event Action<ConsentShown>? ConsentShown;

    public event Action<BaselineChanged>? BaselineChanged;

    public bool IsLive => _rpc.IsLive;

    public async Task<ScanResult> ScanSessionAsync(string sessionId, bool forced, IProgress<Progress>? progress,
        CancellationToken ct)
    {
        var parameters = new LeftoversScanParams { SessionId = sessionId, Forced = forced };
        return await WithProgress(progress, () => _rpc.CallAsync("leftovers.scan", parameters,
            RpcJsonContext.Default.LeftoversScanParams, RpcJsonContext.Default.ScanResult, ct)).ConfigureAwait(false);
    }

    public async Task<ScanResult> ScanStoredAsync(string programId, IProgress<Progress>? progress, CancellationToken ct)
    {
        var parameters = new LeftoversScanParams { ProgramId = programId };
        return await WithProgress(progress, () => _rpc.CallAsync("leftovers.scan", parameters,
            RpcJsonContext.Default.LeftoversScanParams, RpcJsonContext.Default.ScanResult, ct)).ConfigureAwait(false);
    }

    public Task<CandidatesPage> CandidatesAsync(string scanId, uint offset, int limit, CancellationToken ct)
    {
        var parameters = new CandidatesParams { ScanId = scanId, Offset = offset, Limit = limit };
        return _rpc.CallAsync("scan.candidates", parameters, RpcJsonContext.Default.CandidatesParams,
            RpcJsonContext.Default.CandidatesPage, ct);
    }

    public Task<Explanation> ExplainAsync(string scanId, string candidateId, CancellationToken ct)
    {
        var parameters = new ExplainParams { ScanId = scanId, CandidateId = candidateId };
        return _rpc.CallAsync("candidate.explain", parameters, RpcJsonContext.Default.ExplainParams,
            RpcJsonContext.Default.Explanation, ct);
    }

    public Task<PlanCreated> CreatePlanAsync(string scanId, IReadOnlyList<string> selected, CancellationToken ct)
    {
        var parameters = new PlanCreateParams { ScanId = scanId, Selected = [.. selected] };
        return _rpc.CallAsync("plan.create", parameters, RpcJsonContext.Default.PlanCreateParams,
            RpcJsonContext.Default.PlanCreated, ct);
    }

    public async Task<ExecResult> ExecuteAsync(string planId, RestorePoint restorePoint, IProgress<Progress>? progress,
        CancellationToken ct)
    {
        var parameters = new PlanExecuteParams { PlanId = planId, RestorePoint = restorePoint };
        return await WithProgress(progress, () => _rpc.CallAsync("plan.execute", parameters,
            RpcJsonContext.Default.PlanExecuteParams, RpcJsonContext.Default.ExecResult, ct)).ConfigureAwait(false);
    }

    public async Task<UndoResult> UndoAsync(string session, IProgress<Progress>? progress, CancellationToken ct)
    {
        var parameters = new UndoParams { Session = session };
        return await WithProgress(progress, () => _rpc.CallAsync("undo.run", parameters,
            RpcJsonContext.Default.UndoParams, RpcJsonContext.Default.UndoResult, ct)).ConfigureAwait(false);
    }

    public Task<OutcomeResult> RetryHeldAsync(string session, CancellationToken ct)
    {
        var parameters = new SessionParams { Session = session };
        return _rpc.CallAsync("journal.retry_held", parameters, RpcJsonContext.Default.SessionParams,
            RpcJsonContext.Default.OutcomeResult, ct);
    }

    private async Task<T> WithProgress<T>(IProgress<Progress>? progress, Func<Task<T>> call)
    {
        _progress = progress;
        try
        {
            return await call().ConfigureAwait(false);
        }
        finally
        {
            _progress = null;
        }
    }

    private void OnNotification(BrokerNotification notification)
    {
        switch (notification.Method)
        {
            case "scan.progress":
            case "exec.progress":
            case "undo.progress":
            case "uninstall.progress":
                if (_progress is { } progress) progress.Report(Read(notification, RpcJsonContext.Default.Progress));
                break;
            case "consent.shown":
                ConsentShown?.Invoke(Read(notification, RpcJsonContext.Default.ConsentShown));
                break;
            case "baseline.changed":
                BaselineChanged?.Invoke(Read(notification, RpcJsonContext.Default.BaselineChanged));
                break;
        }
    }

    private static T Read<T>(BrokerNotification notification, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> info)
    {
        if (notification.Params.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            throw new InvalidDataException($"the {notification.Method} notification has no params");
        return notification.Params.Deserialize(info)
               ?? throw new InvalidDataException($"the {notification.Method} notification is empty");
    }
}
