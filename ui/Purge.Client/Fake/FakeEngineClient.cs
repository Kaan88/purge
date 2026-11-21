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

    /// <summary>Launch bench stub (M3 design 9.3): when above zero, <c>programs.list</c> answers after 20 ms with this many rows.</summary>
    public int BenchRows { get; init; }

    public async Task<InventoryDoc> ListProgramsAsync(CancellationToken ct = default)
    {
        var doc = LoadSample();
        // An empty sample has nothing to repeat; answer with what it has instead of dividing by zero.
        if (BenchRows <= 0 || doc.Entries.Count == 0) return doc;
        await Task.Delay(20, ct).ConfigureAwait(false);
        var rows = new List<InventoryEntry>(BenchRows);
        for (var i = 0; i < BenchRows; i++)
        {
            var src = doc.Entries[i % doc.Entries.Count];
            rows.Add(i < doc.Entries.Count ? src : src with { ProgramId = $"{src.ProgramId}-{i}", DisplayName = $"{src.DisplayName} {i}" });
        }
        return doc with { Entries = rows };
    }

    private static InventoryDoc LoadSample()
    {
        using var s = Open("Purge.Client.sample-inventory.json");
        var doc = JsonSerializer.Deserialize(s, PurgeJsonContext.Default.InventoryDoc)
                  ?? throw new InvalidDataException("empty inventory");
        if (doc.Schema != InventoryDoc.SchemaId)
            throw new InvalidDataException($"unexpected schema {doc.Schema}");
        return doc;
    }

    public bool CanChangePc => false;

    public event Action<IReadOnlyList<Rpc.ProgramPatch>>? ProgramsPatched { add { } remove { } }

    public Task MeasureSizesAsync(IReadOnlyList<string> programIds, Action<IReadOnlyList<Rpc.ProgramSize>> onBatch, CancellationToken ct = default)
    {
        using var s = Open("Purge.Client.sample-sizes.json");
        var sizes = JsonSerializer.Deserialize(s, PurgeJsonContext.Default.DictionaryStringInt64) ?? new();
        var wanted = programIds.ToHashSet(StringComparer.Ordinal);
        var batch = sizes.Where(kv => wanted.Contains(kv.Key))
            .Select(kv => new Rpc.ProgramSize { ProgramId = kv.Key, Bytes = (ulong)kv.Value }).ToList();
        if (batch.Count > 0) onBatch(batch);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Made-up icons for the sample page: a round dot in a colour per program, so the icon path shows without an
    /// engine. The launch bench stub (<see cref="BenchRows"/>) sends none.
    /// </summary>
    public Task LoadIconsAsync(IReadOnlyList<string> programIds, int px, Action<IReadOnlyList<ProgramIcon>> onBatch, CancellationToken ct = default)
    {
        if (BenchRows > 0 || px < 2) return Task.CompletedTask;
        var batch = new List<ProgramIcon>();
        foreach (var id in programIds)
        {
            var hash = 17;
            foreach (var c in id) hash = hash * 31 + c;
            byte b = (byte)(hash & 0xFF), g = (byte)((hash >> 8) & 0xFF), r = (byte)((hash >> 16) & 0xFF);
            var bgra = new byte[px * px * 4];
            var mid = (px - 1) / 2.0;
            for (var y = 0; y < px; y++)
                for (var x = 0; x < px; x++)
                {
                    var inside = (x - mid) * (x - mid) + (y - mid) * (y - mid) <= mid * mid;
                    var at = (y * px + x) * 4;
                    bgra[at] = b; bgra[at + 1] = g; bgra[at + 2] = r; bgra[at + 3] = inside ? (byte)255 : (byte)0;
                }
            batch.Add(new ProgramIcon(id, px, bgra));
        }
        if (batch.Count > 0) onBatch(batch);
        return Task.CompletedTask;
    }

    public async Task<Rpc.ProgramDetails?> GetProgramAsync(string programId, CancellationToken ct = default)
    {
        var e = (await ListProgramsAsync(ct).ConfigureAwait(false)).Entries.FirstOrDefault(x => x.ProgramId == programId);
        if (e is null) return null;
        return new Rpc.ProgramDetails
        {
            ProgramId = e.ProgramId, Name = e.DisplayName, Publisher = e.Publisher, Version = e.Version,
            Scope = e.Scope == InstallScope.User ? Rpc.InstallScope.User : Rpc.InstallScope.Machine,
            Installer = e.InstallerKind switch
            {
                InstallerKind.Msi => Rpc.InstallerKind.Msi, InstallerKind.Inno => Rpc.InstallerKind.Inno,
                InstallerKind.Nsis => Rpc.InstallerKind.Nsis, InstallerKind.Burn => Rpc.InstallerKind.Burn, _ => Rpc.InstallerKind.Unknown,
            },
            WritableBy = e.WritableBy == WritableBy.User ? Rpc.WritableBy.User : Rpc.WritableBy.Admin,
            InstallLocation = e.InstallLocation, UninstallCommand = e.UninstallString, QuietUninstallCommand = e.QuietUninstallString,
            ProductCode = e.ProductCode,
        };
    }

    /// <summary>Two sample programs "removed outside Purge", so the attention group has something to show.</summary>
    public Task<Rpc.InventoryChanges> GetInventoryChangesAsync(CancellationToken ct = default) =>
        Task.FromResult(new Rpc.InventoryChanges
        {
            Disappeared =
            [
                new Rpc.ProgramRef { ProgramId = "HKU:S-1-5-21-1000000001-2000000002-3000000003-1001|64|Notion", Name = "Notion" },
                new Rpc.ProgramRef { ProgramId = "HKU:S-1-5-21-1000000001-2000000002-3000000003-1001|64|slack", Name = "Slack" },
            ],
        });

    /// <summary>Sample data has no uninstaller to route: the click is disabled before this is reached.</summary>
    public Task<Rpc.RouteInfo> GetUninstallRouteAsync(string programId, CancellationToken ct = default) => NotLive<Rpc.RouteInfo>();

    /// <summary>Sample data never runs an uninstaller.</summary>
    public Task<Rpc.RunUserResult> RunUserUninstallAsync(string programId, bool quiet, Action<Rpc.Progress>? progress = null,
        CancellationToken ct = default) => NotLive<Rpc.RunUserResult>();

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
