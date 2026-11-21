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
/// (crates/purge-rpc, <c>frame.rs</c>), reading and writing the DTOs of <c>Rpc/</c>. One reader thread; requests are
/// numbered from 1 and may overlap. The Programs page's calls are implemented (<c>engine.hello</c>,
/// <c>programs.list</c> with its batches and patches, <c>programs.get</c>, <c>programs.sizes</c>,
/// <c>programs.icons</c>, <c>inventory.changes</c>), and so are the Uninstall pipeline's medium side
/// (<c>uninstall.route</c>, <c>uninstall.run_user</c> with <c>uninstall.progress</c>).
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
    private long _listRequest;
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

    /// <summary>The engine is live, so the Uninstall click can start the broker (the broker is what changes the PC).</summary>
    public bool CanChangePc => true;

    public event Action<IReadOnlyList<Rpc.ProgramPatch>>? ProgramsPatched;

    public async Task<Model.EngineHello> HelloAsync(CancellationToken ct = default)
    {
        var result = await CallAsync("engine.hello", null, null, ct).ConfigureAwait(false);
        var hello = result.Deserialize(Rpc.RpcJsonContext.Default.MediumHello) ?? throw new InvalidDataException("empty engine.hello result");
        return new Model.EngineHello(
            Version: hello.Version,
            Elevated: hello.Elevated,
            UserSid: hello.UserSid,
            ShellSid: hello.ShellSid ?? hello.UserSid,
            Edition: hello.Edition,
            Build: hello.Build.ToString(CultureInfo.InvariantCulture) + (hello.Ubr != 0 ? "." + hello.Ubr.ToString(CultureInfo.InvariantCulture) : ""),
            BaselineAvailable: hello.BaselineAvailable,
            PolicyVersion: hello.PolicyVersion,
            BuildNote: hello.BaselineBuild?.Reason);
    }

    public async Task<InventoryDoc> ListProgramsAsync(CancellationToken ct = default)
    {
        var feed = new ListFeed(patches => Raise(ProgramsPatched, patches));
        await CallAsync("programs.list", null, feed, ct, onSent: id => Interlocked.Exchange(ref _listRequest, (long)id)).ConfigureAwait(false);
        var entries = feed.Rows.Select(ProgramEntries.FromRow).ToList();
        var byId = new Dictionary<string, int>(entries.Count, StringComparer.Ordinal);
        for (var i = 0; i < entries.Count; i++) byId[entries[i].ProgramId] = i;
        foreach (var patch in feed.Close())
            if (byId.TryGetValue(patch.ProgramId, out var at)) entries[at] = ProgramEntries.Apply(entries[at], patch);
        return new InventoryDoc(InventoryDoc.SchemaId, entries, null);
    }

    public Task MeasureSizesAsync(IReadOnlyList<string> programIds, Action<IReadOnlyList<Rpc.ProgramSize>> onBatch, CancellationToken ct = default)
    {
        if (programIds.Count == 0) return Task.CompletedTask;
        return CallAsync("programs.sizes", w =>
        {
            w.WriteStartArray("program_ids");
            foreach (var id in programIds) w.WriteStringValue(id);
            w.WriteEndArray();
        }, new SizeFeed(onBatch), ct);
    }

    public Task LoadIconsAsync(IReadOnlyList<string> programIds, int px, Action<IReadOnlyList<ProgramIcon>> onBatch, CancellationToken ct = default)
    {
        if (programIds.Count == 0) return Task.CompletedTask;
        return CallAsync("programs.icons", w =>
        {
            w.WriteStartArray("program_ids");
            foreach (var id in programIds) w.WriteStringValue(id);
            w.WriteEndArray();
            w.WriteNumber("px", px);
        }, new IconFeed(onBatch), ct);
    }

    public async Task<Rpc.ProgramDetails?> GetProgramAsync(string programId, CancellationToken ct = default)
    {
        try
        {
            var result = await CallAsync("programs.get", w => w.WriteString("program_id", programId), null, ct).ConfigureAwait(false);
            return result.Deserialize(Rpc.RpcJsonContext.Default.ProgramDetails);
        }
        catch (EngineRpcException e) when (e.Kind == "gone")
        {
            return null;
        }
    }

    public async Task<Rpc.InventoryChanges> GetInventoryChangesAsync(CancellationToken ct = default)
    {
        var result = await CallAsync("inventory.changes", null, null, ct).ConfigureAwait(false);
        return result.Deserialize(Rpc.RpcJsonContext.Default.InventoryChanges) ?? throw new InvalidDataException("empty inventory.changes result");
    }

    public async Task<Rpc.RouteInfo> GetUninstallRouteAsync(string programId, CancellationToken ct = default)
    {
        var result = await CallAsync("uninstall.route", w => w.WriteString("program_id", programId), null, ct).ConfigureAwait(false);
        return result.Deserialize(Rpc.RpcJsonContext.Default.RouteInfo) ?? throw new InvalidDataException("empty uninstall.route result");
    }

    public async Task<Rpc.RunUserResult> RunUserUninstallAsync(string programId, bool quiet, Action<Rpc.Progress>? progress = null,
        CancellationToken ct = default)
    {
        var result = await CallAsync("uninstall.run_user", w =>
        {
            w.WriteString("program_id", programId);
            w.WriteBoolean("quiet", quiet);
        }, null, ct, onProgress: progress).ConfigureAwait(false);
        return result.Deserialize(Rpc.RpcJsonContext.Default.RunUserResult) ?? throw new InvalidDataException("empty uninstall.run_user result");
    }

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

    // A callback of the page must not end the reader thread, and so the link.
    private static void Raise<T>(Action<T>? handler, T value)
    {
        try { handler?.Invoke(value); }
        catch (Exception e) when (e is not OutOfMemoryException) { }
    }

    private async Task<JsonElement> CallAsync(string method, Action<Utf8JsonWriter>? writeParams, Feed? feed, CancellationToken ct,
        Action<ulong>? onSent = null, Action<Rpc.Progress>? onProgress = null)
    {
        var id = Interlocked.Increment(ref _nextId);
        var pending = new Pending(feed, onProgress);
        if (_closedReason is { } closed) throw new EngineLinkException(closed);
        _pending[id] = pending;
        try
        {
            onSent?.Invoke(id);
            Send(w =>
            {
                w.WriteString("jsonrpc", "2.0");
                w.WriteNumber("id", id);
                w.WriteString("method", method);
                w.WriteStartObject("params");
                writeParams?.Invoke(w);
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
            var result = await pending.Result.Task.ConfigureAwait(false);
            if (feed is not null)
            {
                // The data follows the reply in notifications, or came before it: wait until all of it is in.
                var started = result.Deserialize(Rpc.RpcJsonContext.Default.Started) ?? throw new InvalidDataException($"empty {method} result");
                await feed.WaitForAsync((int)started.Count, ct).ConfigureAwait(false);
            }
            return result;
        }
        finally
        {
            _pending.TryRemove(id, out _);
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
        else if (root.TryGetProperty("method", out var method) && method.ValueKind == JsonValueKind.String
                 && root.TryGetProperty("params", out var args) && args.ValueKind == JsonValueKind.Object
                 && args.TryGetProperty("request", out var request) && request.TryGetUInt64(out var requestId))
        {
            var name = method.GetString();
            if (_pending.TryGetValue(requestId, out var pending))
            {
                if (pending.Feed is { } feed) feed.Notification(name!, args);
                else if (pending.OnProgress is { } onProgress && name is not null
                         && name.EndsWith(".progress", StringComparison.Ordinal))
                {
                    try
                    {
                        var progress = args.Deserialize(Rpc.RpcJsonContext.Default.Progress);
                        if (progress is not null) Raise(onProgress, progress);
                    }
                    catch (JsonException) { }
                }
            }
            else if (name == "programs.patch" && (long)requestId == Interlocked.Read(ref _listRequest))
            {
                // Patches of a list that already ended: the page applies them to the rows it has.
                var late = args.Deserialize(Rpc.RpcJsonContext.Default.ProgramsPatch);
                if (late is not null) Raise(ProgramsPatched, late.Patches);
            }
        }
        // Other notifications (baseline.changed, progress of the broker's calls) are not the stdio engine's.
    }

    private static Exception ToException(JsonElement error)
    {
        Rpc.ErrorObject? parsed;
        try { parsed = error.Deserialize(Rpc.RpcJsonContext.Default.ErrorObject); }
        catch (JsonException)
        {
            // An error whose data this client does not know is still an error, and must not end the link.
            var code = error.TryGetProperty("code", out var c) && c.TryGetInt32(out var n) ? n : 0;
            var text = error.TryGetProperty("message", out var m) && m.ValueKind == JsonValueKind.String ? m.GetString() : null;
            string? kindText = null;
            if (error.TryGetProperty("data", out var d) && d.ValueKind == JsonValueKind.Object && d.TryGetProperty("kind", out var k) && k.ValueKind == JsonValueKind.String)
                kindText = k.GetString();
            return new EngineRpcException(code, kindText, string.IsNullOrEmpty(text) ? "The engine reported an error." : text);
        }
        var kind = parsed?.Data?.Kind;
        var message = parsed?.Data?.Message ?? parsed?.Message;
        return new EngineRpcException(parsed?.Code ?? 0, kind, string.IsNullOrEmpty(message) ? "The engine reported an error." : message);
    }

    private void Fail(string reason)
    {
        _closedReason ??= reason;
        foreach (var pending in _pending.Values) pending.Fail(new EngineLinkException(reason));
    }

    private sealed class Pending(Feed? feed, Action<Rpc.Progress>? onProgress)
    {
        public TaskCompletionSource<JsonElement> Result { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Feed? Feed { get; } = feed;
        public Action<Rpc.Progress>? OnProgress { get; } = onProgress;

        public void Fail(Exception e)
        {
            Result.TrySetException(e);
            Feed?.Fail(e);
        }

        public void Cancel(CancellationToken ct)
        {
            Result.TrySetCanceled(ct);
            Feed?.Cancel(ct);
        }
    }

    /// <summary>The notifications of one request: counted, so the call ends when every item the reply promised is in.</summary>
    private abstract class Feed
    {
        private readonly object _gate = new();
        private readonly TaskCompletionSource _done = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _received;
        private int _expected = -1;

        /// <summary>A notification of this request, on the reader thread.</summary>
        public abstract void Notification(string method, JsonElement args);

        protected void Count(int items)
        {
            lock (_gate)
            {
                _received += items;
                Check();
            }
        }

        public Task WaitForAsync(int count, CancellationToken ct)
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
            if (_expected >= 0 && _received >= _expected) _done.TrySetResult();
        }

        public void Fail(Exception e) => _done.TrySetException(e);

        public void Cancel(CancellationToken ct) => _done.TrySetCanceled(ct);
    }

    /// <summary><c>programs.batch</c> rows and <c>programs.patch</c> patches of one <c>programs.list</c>.</summary>
    private sealed class ListFeed(Action<IReadOnlyList<Rpc.ProgramPatch>> late) : Feed
    {
        private readonly object _gate = new();
        private readonly List<Rpc.ProgramPatch> _patches = [];
        private bool _closed;

        public List<Rpc.ProgramRow> Rows { get; } = [];

        public override void Notification(string method, JsonElement args)
        {
            if (method == "programs.batch")
            {
                var batch = args.Deserialize(Rpc.RpcJsonContext.Default.ProgramsBatch);
                if (batch is null) return;
                lock (_gate) Rows.AddRange(batch.Rows);
                Count(batch.Rows.Count);
            }
            else if (method == "programs.patch")
            {
                var patch = args.Deserialize(Rpc.RpcJsonContext.Default.ProgramsPatch);
                if (patch is null) return;
                bool closed;
                lock (_gate)
                {
                    closed = _closed;
                    if (!closed) _patches.AddRange(patch.Patches);
                }
                if (closed) late(patch.Patches);
            }
        }

        /// <summary>The patches received so far; later ones go to the <c>late</c> callback.</summary>
        public List<Rpc.ProgramPatch> Close()
        {
            lock (_gate)
            {
                _closed = true;
                return _patches;
            }
        }
    }

    private sealed class SizeFeed(Action<IReadOnlyList<Rpc.ProgramSize>> onBatch) : Feed
    {
        public override void Notification(string method, JsonElement args)
        {
            if (method != "size.ready") return;
            var ready = args.Deserialize(Rpc.RpcJsonContext.Default.SizeReady);
            if (ready is null) return;
            Raise(onBatch, ready.Sizes);
            Count(ready.Sizes.Count);
        }
    }

    private sealed class IconFeed(Action<IReadOnlyList<ProgramIcon>> onBatch) : Feed
    {
        public override void Notification(string method, JsonElement args)
        {
            if (method != "icon.batch") return;
            var batch = args.Deserialize(Rpc.RpcJsonContext.Default.IconBatch);
            if (batch is null) return;
            Raise(onBatch, batch.Icons.Select(ProgramEntries.ToIcon).ToList());
            Count(batch.Icons.Count);
        }
    }
}
