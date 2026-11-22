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

    /// <summary>
    /// True when the Uninstall click can start the flow: the engine is live, so it can route the program and start
    /// the elevated broker. The sample client answers false, and its page disables Uninstall with the reason.
    /// </summary>
    bool CanChangePc { get; }

    /// <summary>
    /// Patches that arrived after the <c>programs.list</c> reply (the engine normally sends them before it). Raised on
    /// the client's reader thread.
    /// </summary>
    event Action<IReadOnlyList<Rpc.ProgramPatch>>? ProgramsPatched;

    /// <summary>
    /// <c>programs.sizes</c>: measures the given programs; <paramref name="onBatch"/> gets each <c>size.ready</c> batch
    /// (bytes null when a size could not be measured) on the client's reader thread. Completes when the engine has
    /// answered for every id.
    /// </summary>
    Task MeasureSizesAsync(IReadOnlyList<string> programIds, Action<IReadOnlyList<Rpc.ProgramSize>> onBatch, CancellationToken ct = default);

    /// <summary>
    /// <c>programs.icons</c>: <paramref name="px"/> pixel icons, in the order given (viewport first), delivered per
    /// <c>icon.batch</c> on the client's reader thread. An icon that could not be read arrives with null pixels.
    /// </summary>
    Task LoadIconsAsync(IReadOnlyList<string> programIds, int px, Action<IReadOnlyList<ProgramIcon>> onBatch, CancellationToken ct = default);

    /// <summary><c>programs.get</c>: the details pane's data of one program; null when the engine no longer knows it.</summary>
    Task<Rpc.ProgramDetails?> GetProgramAsync(string programId, CancellationToken ct = default);

    /// <summary>
    /// <c>inventory.changes</c>: programs gone or new since the list the engine stored at the last <c>programs.list</c>.
    /// The engine stores the new list when it ends a <c>programs.list</c>, so ask before listing.
    /// </summary>
    Task<Rpc.InventoryChanges> GetInventoryChangesAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>uninstall.route</c>: where the program's uninstaller belongs (<c>broker</c> or <c>medium</c>), and the exact
    /// interactive and quiet command lines it will run, with their signer and the processes that hold the program.
    /// The medium engine never runs a broker-route command; the broker never runs a medium-route one.
    /// </summary>
    Task<Rpc.RouteInfo> GetUninstallRouteAsync(string programId, CancellationToken ct = default);

    /// <summary>
    /// <c>uninstall.run_user</c>: runs a medium-route uninstaller at this process's own level, with the command
    /// <see cref="GetUninstallRouteAsync"/> showed for the same <paramref name="quiet"/> choice. Progress arrives as
    /// <c>uninstall.progress</c> on the client's reader thread.
    /// </summary>
    Task<Rpc.RunUserResult> RunUserUninstallAsync(string programId, bool quiet, Action<Rpc.Progress>? progress = null,
        CancellationToken ct = default);

    /// <summary>
    /// <c>programs.forecast</c> (proposed, not in the engine yet): expected leftovers for the given programs. Asked
    /// in small batches after the first frame; ids without an answer are "not known yet".
    /// </summary>
    Task<IReadOnlyList<LeftoverForecast>> GetForecastsAsync(IReadOnlyList<string> programIds, CancellationToken ct = default);

    /// <summary>
    /// <c>history.index</c>: the sessions of <c>sessions\index.json</c>, newest first, with quarantine usage and cap per
    /// volume. The medium engine answers it, so showing History never starts the broker (design 6.3, page table).
    /// </summary>
    Task<Rpc.HistoryIndex> GetHistoryIndexAsync(CancellationToken ct = default);

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
