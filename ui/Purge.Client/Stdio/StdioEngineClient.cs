using System.Buffers;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Purge.Client.Model;

namespace Purge.Client.Stdio;

/// <summary>The engine answered a request with a JSON-RPC error (<c>error.data.kind</c> says which).</summary>
public sealed class EngineRpcException(int code, string? kind, string message) : Exception(message)
{
    public int Code { get; } = code;

    /// <summary><c>error.data.kind</c> (for example <c>runtime</c>), when the engine gave one.</summary>
    public string? Kind { get; } = kind;
}

/// <summary>The link to the engine broke: it could not be written to, or it ended.</summary>
public sealed class EngineLinkException(string message) : Exception(message);

/// <summary>
/// The product link to <c>purge-engine --stdio</c>: newline-delimited JSON-RPC 2.0 over the engine's stdin and stdout
/// (crates/purge-rpc, <c>frame.rs</c>). One reader thread; requests are numbered from 1 and may overlap. Only the
/// calls the shell makes at start are implemented (<c>engine.hello</c>, <c>programs.list</c>); the rest need the
/// broker (M3-BROKER-FLOW) and say so.
/// </summary>
public sealed class StdioEngineClient : IEngineClient
{
    private const string NeedsBroker = "This build only lists programs. Scanning and removing arrive with the Purge security prompt.";

    private readonly Stream _input;
    private readonly Stream _output;
    private readonly IDisposable? _owner;
    private readonly Func<int, int?>? _exitCode;
    private readonly ConcurrentDictionary<ulong, Pending> _pending = new();
    private readonly object _writeGate = new();
    private readonly ArrayBufferWriter<byte> _buffer = new();
    private ulong _nextId;
    private volatile string? _closedReason;
    private int _disposed;

    private StdioEngineClient(Stream input, Stream output, IDisposable? owner, Func<int, int?>? exitCode)
    {
        _input = input;
        _output = output;
        _owner = owner;
        _exitCode = exitCode;
        new Thread(ReadLoop) { IsBackground = true, Name = "purge-engine-reader" }.Start();
    }

    /// <summary>Starts <c>purge-engine --stdio</c> in a kill-on-close job; throws when it cannot be started.</summary>
    public static StdioEngineClient Start(string enginePath, string arguments = "--stdio")
    {
        var process = EngineProcess.Start(enginePath, arguments);
        return new StdioEngineClient(process.Input, process.Output, process, process.ExitCode);
    }

    /// <summary>A client over two streams (<paramref name="input"/>: requests out; <paramref name="output"/>: replies in).</summary>
    public static StdioEngineClient Over(Stream input, Stream output) => new(input, output, null, null);

    public bool IsLive => true;

    public async Task<EngineHello> HelloAsync(CancellationToken ct = default)
    {
        var result = await CallAsync("engine.hello", null, ct).ConfigureAwait(false);
        var hello = result.Deserialize(WireJsonContext.Default.WireHello) ?? throw new InvalidDataException("empty engine.hello result");
        return new EngineHello(
            Version: hello.Version,
            Elevated: hello.Elevated,
            UserSid: hello.UserSid,
            ShellSid: hello.ShellSid ?? hello.UserSid,
            Edition: hello.Edition,
            Build: hello.Build.ToString(CultureInfo.InvariantCulture)
                   + (hello.Ubr is { } ubr ? "." + ubr.ToString(CultureInfo.InvariantCulture) : ""),
            BaselineAvailable: hello.BaselineAvailable,
            PolicyVersion: hello.PolicyVersion,
            BuildNote: hello.BaselineBuild?.Reason);
    }

    public async Task<InventoryDoc> ListProgramsAsync(CancellationToken ct = default)
    {
        var rows = new RowCollector();
        try
        {
            var result = await CallAsync("programs.list", rows, ct).ConfigureAwait(false);
            var started = result.Deserialize(WireJsonContext.Default.WireStarted) ?? throw new InvalidDataException("empty programs.list result");
            var all = await rows.WaitForAsync(started.Count, ct).ConfigureAwait(false);
            return new InventoryDoc(InventoryDoc.SchemaId, all.Select(ToEntry).ToList(), null);
        }
        finally
        {
            // The request stays registered until its rows are in: they follow the reply.
            foreach (var (id, pending) in _pending)
                if (ReferenceEquals(pending.Rows, rows)) _pending.TryRemove(id, out _);
        }
    }

    // programs.sizes and programs.forecast are separate calls that come later; until then "not known yet".
    public Task<IReadOnlyDictionary<string, long>> GetSizesAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyDictionary<string, long>>(new Dictionary<string, long>());

    public Task<IReadOnlyList<LeftoverForecast>> GetForecastsAsync(IReadOnlyList<string> programIds, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<LeftoverForecast>>([]);

    public Task<QuarantineStatus> GetQuarantineAsync(CancellationToken ct = default) => NeedsBrokerCall<QuarantineStatus>();

    public Task<LeftoverPlan> ScanAsync(string programId, string programName, ScanKind kind, IProgress<EngineProgress>? progress = null,
        CancellationToken ct = default) => NeedsBrokerCall<LeftoverPlan>();

    public Task<ExecResult> ExecAsync(LeftoverPlan plan, IReadOnlyList<string> selectedIds, IProgress<EngineProgress>? progress = null,
        CancellationToken ct = default) => NeedsBrokerCall<ExecResult>();

    public Task<UndoResult> UndoSessionAsync(string sessionId, CancellationToken ct = default) => NeedsBrokerCall<UndoResult>();

    public Task<IReadOnlyList<PendingSession>> PendingRecoveryAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<PendingSession>>([]);

    public Task<RecoveryResult> RecoverAsync(bool rollback, CancellationToken ct = default) => NeedsBrokerCall<RecoveryResult>();

    private static Task<T> NeedsBrokerCall<T>() => Task.FromException<T>(new InvalidOperationException(NeedsBroker));

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Fail("The engine link was closed.");
            // Closing the job ends the engine (and what it started); the reader then sees the end of the stream.
            try { _owner?.Dispose(); } catch (IOException) { }
            try { _input.Dispose(); } catch (IOException) { }
        }
        return ValueTask.CompletedTask;
    }

    private static InventoryEntry ToEntry(WireProgramRow row)
    {
        // A program id is "HKLM|64|key" or "HKU:<sid>|32|key".
        var parts = row.ProgramId.Split('|', 3);
        var hive = parts[0];
        var view = parts.Length > 1 && parts[1] == "32" ? RegistryView.K32 : RegistryView.K64;
        var key = parts.Length > 2 ? parts[2] : row.ProgramId;
        var sid = hive.StartsWith("HKU:", StringComparison.Ordinal) ? hive[4..] : null;
        var software = sid is null ? "SOFTWARE" : "Software";
        var wow = view == RegistryView.K32 ? "\\WOW6432Node" : "";
        var keyPath = $"{(sid is null ? "HKLM" : "HKU\\" + sid)}\\{software}{wow}\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{key}";
        IReadOnlyList<InstallTimeEvidence>? time = row.InstallTime is { } t ? [new InstallTimeEvidence(InstallTimeSource.ArpInstallDate, t)] : null;
        return new InventoryEntry(
            ProgramId: row.ProgramId, KeyPath: keyPath, HiveSid: sid, View: view, DisplayName: row.Name, Version: row.Version,
            Publisher: row.Publisher,
            // The raw ARP row has no flags yet; programs.patch fills in what the engine learns later.
            Flags: new RawFlags(SystemComponent: false, HasDisplayName: true, HasUninstallString: true, ParentKey: null, ReleaseType: null,
                WindowsInstaller: false),
            InstallerKind: InstallerKind.Unknown, Scope: row.Scope, ProductCode: null, UpgradeCode: null, InnoAppId: null,
            WritableBy: row.Scope == InstallScope.Machine ? WritableBy.Admin : WritableBy.User, InstallLocation: null,
            UninstallString: null, QuietUninstallString: null, DisplayIcon: null, InstallTimeEvidence: time, Msi: null);
    }

    private async Task<JsonElement> CallAsync(string method, RowCollector? rows, CancellationToken ct)
    {
        var id = Interlocked.Increment(ref _nextId);
        var pending = new Pending(rows);
        if (_closedReason is { } closed) throw new EngineLinkException(closed);
        _pending[id] = pending;
        try
        {
            Send(w =>
            {
                w.WriteString("jsonrpc", "2.0");
                w.WriteNumber("id", id);
                w.WriteString("method", method);
                w.WriteStartObject("params");
                w.WriteEndObject();
            });
            // The reader may have failed between the check above and the registration.
            if (_closedReason is { } late) pending.Fail(new EngineLinkException(late));
            using var registration = ct.Register(() =>
            {
                try { Send(w => { w.WriteString("jsonrpc", "2.0"); w.WriteString("method", "$/cancel"); w.WriteStartObject("params"); w.WriteNumber("request", id); w.WriteEndObject(); }); }
                catch (EngineLinkException) { }
                pending.Cancel(ct);
            });
            return await pending.Result.Task.ConfigureAwait(false);
        }
        finally
        {
            if (rows is null) _pending.TryRemove(id, out _);
        }
    }

    private void Send(Action<Utf8JsonWriter> body)
    {
        lock (_writeGate)
        {
            _buffer.Clear();
            using (var w = new Utf8JsonWriter(_buffer))
            {
                w.WriteStartObject();
                body(w);
                w.WriteEndObject();
            }
            _buffer.GetSpan(1)[0] = (byte)'\n';
            _buffer.Advance(1);
            try
            {
                _input.Write(_buffer.WrittenSpan);
                _input.Flush();
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException)
            {
                var reason = _closedReason ?? "The engine is not running.";
                throw new EngineLinkException(reason);
            }
        }
    }

    private void ReadLoop()
    {
        string reason;
        try
        {
            using var reader = new StreamReader(_output, new UTF8Encoding(false), false, 64 * 1024);
            while (reader.ReadLine() is { } line)
            {
                if (line.Length == 0) continue;
                Dispatch(line);
            }
            reason = "The engine ended" + ExitText() + ".";
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
            reason = "The engine ended" + ExitText() + ".";
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            reason = "The engine sent a line that is not JSON-RPC: " + e.Message;
        }
        Fail(reason);
    }

    private string ExitText() =>
        _exitCode?.Invoke(1500) is { } code ? $" (exit code {code.ToString(CultureInfo.InvariantCulture)})" : "";

    private void Dispatch(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return;
        if (root.TryGetProperty("id", out var idElement))
        {
            if (idElement.ValueKind != JsonValueKind.Number || !idElement.TryGetUInt64(out var id) || !_pending.TryGetValue(id, out var pending)) return;
            if (root.TryGetProperty("error", out var error)) pending.Fail(ToException(error));
            else if (root.TryGetProperty("result", out var result)) pending.Result.TrySetResult(result.Clone());
            else pending.Fail(new InvalidDataException("a response has neither result nor error"));
        }
        else if (root.TryGetProperty("method", out var method) && method.ValueKind == JsonValueKind.String && method.GetString() == "programs.batch"
                 && root.TryGetProperty("params", out var args))
        {
            var batch = args.Deserialize(WireJsonContext.Default.WireProgramsBatch);
            if (batch is not null && _pending.TryGetValue(batch.Request, out var pending)) pending.Rows?.Add(batch.Rows);
        }
        // Other notifications (programs.patch, icon.batch, size.ready, inventory changes) are not read yet.
    }

    private static Exception ToException(JsonElement error)
    {
        var code = error.TryGetProperty("code", out var c) && c.TryGetInt32(out var n) ? n : 0;
        var message = error.TryGetProperty("message", out var m) ? m.GetString() : null;
        string? kind = null;
        if (error.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Object)
        {
            var d = data.Deserialize(WireJsonContext.Default.WireErrorData);
            kind = d?.Kind;
            message = d?.Message ?? message;
        }
        return new EngineRpcException(code, kind, message ?? "The engine reported an error.");
    }

    private void Fail(string reason)
    {
        _closedReason ??= reason;
        foreach (var pending in _pending.Values) pending.Fail(new EngineLinkException(reason));
    }

    private sealed class Pending(RowCollector? rows)
    {
        public TaskCompletionSource<JsonElement> Result { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public RowCollector? Rows { get; } = rows;

        public void Fail(Exception e)
        {
            Result.TrySetException(e);
            Rows?.Fail(e);
        }

        public void Cancel(CancellationToken ct)
        {
            Result.TrySetCanceled(ct);
            Rows?.Cancel(ct);
        }
    }

    /// <summary>The rows of one <c>programs.list</c>: they arrive in notifications, before or after the reply that counts them.</summary>
    private sealed class RowCollector
    {
        private readonly object _gate = new();
        private readonly List<WireProgramRow> _rows = [];
        private readonly TaskCompletionSource<List<WireProgramRow>> _done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _expected = -1;

        public void Add(List<WireProgramRow> batch)
        {
            lock (_gate)
            {
                _rows.AddRange(batch);
                Check();
            }
        }

        public Task<List<WireProgramRow>> WaitForAsync(int count, CancellationToken ct)
        {
            lock (_gate)
            {
                _expected = count;
                Check();
            }
            return _done.Task.WaitAsync(ct);
        }

        private void Check()
        {
            if (_expected >= 0 && _rows.Count >= _expected) _done.TrySetResult(_rows);
        }

        public void Fail(Exception e) => _done.TrySetException(e);

        public void Cancel(CancellationToken ct) => _done.TrySetCanceled(ct);
    }
}
