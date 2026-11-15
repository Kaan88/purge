using Purge.Client.Model;

namespace Purge.Client;

/// <summary>
/// The UI's view of <c>purge-engine</c>. One method per JSON-RPC call the shell needs so far
/// (ENGINE_PLAN.md §3.3). The real implementation speaks newline-delimited JSON-RPC 2.0 over the stdio pipes
/// of <c>purge-engine --stdio</c> (and later the broker pipe); <see cref="FakeEngineClient"/> stands in until then.
/// </summary>
public interface IEngineClient : IAsyncDisposable
{
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
}
