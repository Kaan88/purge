using System.Text.Json;
using Purge.Client.Model;

namespace Purge.Client;

/// <summary>
/// Stub engine: answers from embedded sample JSON shaped like the real replies. No process, no I/O beyond the
/// assembly's own resources. Replaced by the stdio JSON-RPC client in M3.
/// </summary>
public sealed class FakeEngineClient : IEngineClient
{
    public Task<EngineHello> HelloAsync(CancellationToken ct = default) =>
        Task.FromResult(new EngineHello(
            Version: "0.0.0-stub",
            Elevated: false,
            UserSid: "S-1-5-21-1000000001-2000000002-3000000003-1001",
            ShellSid: "S-1-5-21-1000000001-2000000002-3000000003-1001",
            Edition: "Professional",
            Build: "26300",
            BaselineAvailable: true,
            PolicyVersion: "0"));

    public Task<InventoryDoc> ListProgramsAsync(CancellationToken ct = default)
    {
        using var s = Open("Purge.Client.sample-inventory.json");
        var doc = JsonSerializer.Deserialize(s, PurgeJsonContext.Default.InventoryDoc)
                  ?? throw new InvalidDataException("empty inventory");
        if (doc.Schema != InventoryDoc.SchemaId)
            throw new InvalidDataException($"unexpected schema {doc.Schema}");
        return Task.FromResult(doc);
    }

    public Task<IReadOnlyDictionary<string, long>> GetSizesAsync(CancellationToken ct = default)
    {
        using var s = Open("Purge.Client.sample-sizes.json");
        IReadOnlyDictionary<string, long> sizes =
            JsonSerializer.Deserialize(s, PurgeJsonContext.Default.DictionaryStringInt64) ?? new();
        return Task.FromResult(sizes);
    }

    private List<LeftoverForecast>? _forecasts;

    public async Task<IReadOnlyList<LeftoverForecast>> GetForecastsAsync(IReadOnlyList<string> programIds, CancellationToken ct = default)
    {
        // A short delay per batch, so the UI's "not known yet" → value path is exercised like with the real engine.
        await Task.Delay(120, ct).ConfigureAwait(false);
        if (_forecasts is null)
        {
            using var s = Open("Purge.Client.sample-forecast.json");
            _forecasts = JsonSerializer.Deserialize(s, PurgeJsonContext.Default.ListLeftoverForecast) ?? [];
        }
        var wanted = programIds.ToHashSet(StringComparer.Ordinal);
        return _forecasts.Where(f => wanted.Contains(f.ProgramId)).ToList();
    }

    public Task<QuarantineStatus> GetQuarantineAsync(CancellationToken ct = default)
    {
        using var s = Open("Purge.Client.sample-quarantine.json");
        return Task.FromResult(JsonSerializer.Deserialize(s, PurgeJsonContext.Default.QuarantineStatus)
                               ?? throw new InvalidDataException("empty quarantine status"));
    }

    public bool IsLive => false;

    public Task<LeftoverPlan> ScanAsync(string programId, string programName, ScanKind kind, IProgress<EngineProgress>? progress = null,
        CancellationToken ct = default) => NotLive<LeftoverPlan>();

    public Task<ExecResult> ExecAsync(LeftoverPlan plan, IReadOnlyList<string> selectedIds, IProgress<EngineProgress>? progress = null,
        CancellationToken ct = default) => NotLive<ExecResult>();

    public Task<UndoResult> UndoSessionAsync(string sessionId, CancellationToken ct = default) => NotLive<UndoResult>();

    public Task<IReadOnlyList<PendingSession>> PendingRecoveryAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<PendingSession>>([]);

    public Task<RecoveryResult> RecoverAsync(bool rollback, CancellationToken ct = default) => NotLive<RecoveryResult>();

    private static Task<T> NotLive<T>() =>
        Task.FromException<T>(new InvalidOperationException("Sample data: no engine is connected, so nothing can be scanned, moved or put back."));

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private static Stream Open(string name) =>
        typeof(FakeEngineClient).Assembly.GetManifestResourceStream(name)
        ?? throw new InvalidOperationException($"missing resource {name}");
}
