using Purge.Client.Model;

namespace Purge.Client;

/// <summary>
/// The UI's view of <c>purge-engine</c>. One method per JSON-RPC call the shell needs so far
/// (ENGINE_PLAN.md §3.3). Today <see cref="Cli.CliEngineClient"/> runs the engine's CLI verbs as child processes
/// (the stdio JSON-RPC transport of M3 replaces it), and <see cref="FakeEngineClient"/> answers from sample JSON.
/// </summary>
public interface IEngineClient : IAsyncDisposable
{
    /// <summary>True when the client talks to a real engine (scan, remove and undo work); false for sample data.</summary>
    bool IsLive { get; }

    /// <summary><c>engine.hello</c>.</summary>
    Task<EngineHello> HelloAsync(CancellationToken ct = default);

    /// <summary><c>programs.list</c>: the inventory document (the raw ARP batch).</summary>
    Task<InventoryDoc> ListProgramsAsync(CancellationToken ct = default);

    /// <summary><c>programs.sizes</c>: measured size in bytes per program id; missing ids are not measured yet.</summary>
    Task<IReadOnlyDictionary<string, long>> GetSizesAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>programs.forecast</c> (proposed, not in the engine yet): expected leftovers for the given programs. Asked
    /// in small batches after the first frame; ids without an answer are "not known yet".
    /// </summary>
    Task<IReadOnlyList<LeftoverForecast>> GetForecastsAsync(IReadOnlyList<string> programIds, CancellationToken ct = default);

    /// <summary><c>quarantine.status</c> (proposed): use per volume and one entry per cleanup.</summary>
    Task<QuarantineStatus> GetQuarantineAsync(CancellationToken ct = default);

    /// <summary>
    /// Records a program, optionally runs its quiet uninstaller, and scans for its leftovers. Progress lines go to
    /// <paramref name="progress"/>.
    /// </summary>
    Task<LeftoverPlan> ScanAsync(string programId, string programName, ScanKind kind, IProgress<EngineProgress>? progress = null,
        CancellationToken ct = default);

    /// <summary>Moves the selected items of a plan to quarantine (removes registry entries with a backup).</summary>
    Task<ExecResult> ExecAsync(LeftoverPlan plan, IReadOnlyList<string> selectedIds, IProgress<EngineProgress>? progress = null,
        CancellationToken ct = default);

    /// <summary>Puts back everything a session changed.</summary>
    Task<UndoResult> UndoSessionAsync(string sessionId, CancellationToken ct = default);

    /// <summary>Sessions that were interrupted and wait for <see cref="RecoverAsync"/>.</summary>
    Task<IReadOnlyList<PendingSession>> PendingRecoveryAsync(CancellationToken ct = default);

    /// <summary>Finishes (<paramref name="rollback"/> false) or rolls back every interrupted session.</summary>
    Task<RecoveryResult> RecoverAsync(bool rollback, CancellationToken ct = default);
}
