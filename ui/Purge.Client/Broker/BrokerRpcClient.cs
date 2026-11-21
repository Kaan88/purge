using System.Buffers;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Purge.Client.Rpc;

namespace Purge.Client.Broker;

/// <summary>The broker answered with a JSON-RPC error (<c>error.data.kind</c> says which).</summary>
public sealed class BrokerRpcException(int code, string? kind, string message, ErrorData? data = null) : Exception(message)
{
    public int Code { get; } = code;

    /// <summary><c>error.data.kind</c> (for example <c>runtime</c> or <c>gone</c>), when the broker gave one.</summary>
    public string? Kind { get; } = kind;

    /// <summary>
    /// The whole <c>error.data</c> object: <c>exit_code</c> and <c>forced_offered</c> of an
    /// <c>uninstall_failed</c>, or the route of a <c>wrong_route</c>. Null when the broker sent none.
    /// </summary>
    public ErrorData? Details { get; } = data;
}

/// <summary>The link to the broker broke: it could not be written to, or it ended.</summary>
public sealed class BrokerLinkException(string message) : Exception(message);

/// <summary>One notification the broker sent (for example <c>baseline.changed</c> or <c>scan.progress</c>).</summary>
/// <param name="Method">The method name; notifications carry no id.</param>
/// <param name="Params">The <c>params</c> member, or a null element when the notification has none.</param>
public sealed record BrokerNotification(string Method, JsonElement Params);

/// <summary>
/// The product link to <c>purge-broker.exe</c>: one duplex stream carrying newline-delimited JSON-RPC 2.0
/// (crates/purge-rpc, <c>frame.rs</c>), exactly as the stdio link does. The broker is the pipe server; the
/// caller has already passed the server check (<see cref="BrokerLauncher"/>) before this class exists.
/// One reader thread; requests are numbered from 1 and may overlap; notifications go to <see cref="Notification"/>.
/// Cancelling a call sends <c>$/cancel</c> and ends the call locally, as the stdio client does.
/// Every document is read and written through the source-generated <see cref="RpcJsonContext"/>, so no reflection
/// is used at run time.
/// </summary>
public sealed class BrokerRpcClient : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly bool _ownsStream;
    private readonly ConcurrentDictionary<ulong, Pending> _pending = new();
    private readonly object _writeGate = new();
    private readonly ArrayBufferWriter<byte> _buffer = new();
    private ulong _nextId;
    private volatile string? _closedReason;
    private int _disposed;

    private BrokerRpcClient(Stream duplex, bool ownsStream)
    {
        _stream = duplex;
        _ownsStream = ownsStream;
        new Thread(ReadLoop) { IsBackground = true, Name = "purge-broker-reader" }.Start();
    }

    /// <summary>A client over an already connected duplex stream (the broker's pipe, or a test's).</summary>
    /// <param name="duplex">The connected stream: requests out, responses and notifications in.</param>
    /// <param name="ownsStream">Whether disposing the client closes <paramref name="duplex"/>.</param>
    public static BrokerRpcClient Over(Stream duplex, bool ownsStream = false) => new(duplex, ownsStream);

    /// <summary>Whether the link is still open (the broker did not end it).</summary>
    public bool IsLive => _closedReason is null;

    /// <summary>Why the link ended, in a sentence for the UI; null while it is live.</summary>
    public string? ClosedReason => _closedReason;

    /// <summary>Every notification the broker sends, on the reader thread. Handlers must not throw; a throw is ignored.</summary>
    public event Action<BrokerNotification>? Notification;

    /// <summary><c>engine.hello</c>: the first request on the broker pipe.</summary>
    public Task<EngineHello> HelloAsync(CancellationToken ct = default) =>
        CallAsync("engine.hello", RpcJsonContext.Default.EngineHello, ct);

    /// <summary><c>broker.shutdown</c>: true when the broker had nothing running and is exiting.</summary>
    public Task<ShutdownResult> ShutdownAsync(CancellationToken ct = default) =>
        CallAsync("broker.shutdown", RpcJsonContext.Default.ShutdownResult, ct);

    /// <summary>A request whose result the caller reads as raw JSON (for example one that starts a notification stream).</summary>
    public async Task<JsonElement> CallAsync(string method, JsonElement? parameters = null, CancellationToken ct = default)
    {
        var id = Interlocked.Increment(ref _nextId);
        var pending = new Pending();
        if (_closedReason is { } closed) throw new BrokerLinkException(closed);
        _pending[id] = pending;
        try
        {
            Send(id, method, parameters);
            // The reader may have failed between the check above and the registration.
            if (_closedReason is { } late) pending.Fail(new BrokerLinkException(late));
            using var registration = ct.Register(() =>
            {
                try { SendCancel(id); }
                catch (BrokerLinkException) { }
                pending.Cancel(ct);
            });
            return await pending.Result.Task.ConfigureAwait(false);
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    /// <summary>A request with typed parameters; both types come from <see cref="RpcJsonContext"/>.</summary>
    public Task<TResult> CallAsync<TParams, TResult>(string method, TParams parameters, JsonTypeInfo<TParams> paramsInfo,
        JsonTypeInfo<TResult> resultInfo, CancellationToken ct = default)
        where TParams : notnull
    {
        var element = JsonSerializer.SerializeToElement(parameters, paramsInfo);
        return TypedAsync(method, element, resultInfo, ct);
    }

    /// <summary>A request with no parameters whose typed result comes from <see cref="RpcJsonContext"/>.</summary>
    public Task<TResult> CallAsync<TResult>(string method, JsonTypeInfo<TResult> resultInfo, CancellationToken ct = default) =>
        TypedAsync(method, null, resultInfo, ct);

    private async Task<TResult> TypedAsync<TResult>(string method, JsonElement? parameters, JsonTypeInfo<TResult> resultInfo,
        CancellationToken ct)
    {
        var result = await CallAsync(method, parameters, ct).ConfigureAwait(false);
        try
        {
            return result.Deserialize(resultInfo)
                   ?? throw new InvalidDataException($"the {method} result is null, not a {resultInfo.Type.Name}");
        }
        catch (JsonException e)
        {
            throw new InvalidDataException($"the {method} result is not a {resultInfo.Type.Name}: {e.Message}", e);
        }
    }

    private void Send(ulong id, string method, JsonElement? parameters)
    {
        lock (_writeGate)
        {
            _buffer.Clear();
            using (var w = new Utf8JsonWriter(_buffer))
            {
                w.WriteStartObject();
                w.WriteString("jsonrpc", "2.0");
                w.WriteNumber("id", id);
                w.WriteString("method", method);
                if (parameters is { ValueKind: not JsonValueKind.Null and not JsonValueKind.Undefined } p)
                {
                    w.WritePropertyName("params");
                    p.WriteTo(w);
                }
                w.WriteEndObject();
            }
            WriteLineLocked();
        }
    }

    private void SendCancel(ulong request)
    {
        lock (_writeGate)
        {
            _buffer.Clear();
            using (var w = new Utf8JsonWriter(_buffer))
            {
                w.WriteStartObject();
                w.WriteString("jsonrpc", "2.0");
                w.WriteString("method", "$/cancel");
                w.WriteStartObject("params");
                w.WriteNumber("request", request);
                w.WriteEndObject();
                w.WriteEndObject();
            }
            WriteLineLocked();
        }
    }

    private void WriteLineLocked()
    {
        _buffer.GetSpan(1)[0] = (byte)'\n';
        _buffer.Advance(1);
        try
        {
            _stream.Write(_buffer.WrittenSpan);
            _stream.Flush();
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
            throw new BrokerLinkException(_closedReason ?? "The administrator part is not running.");
        }
    }

    private void ReadLoop()
    {
        string reason;
        try
        {
            using var reader = new StreamReader(_stream, new UTF8Encoding(false), false, 64 * 1024);
            while (reader.ReadLine() is { } line)
            {
                if (line.Length == 0) continue;
                Dispatch(line);
            }
            reason = "The administrator part ended.";
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
            reason = "The administrator part ended.";
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException)
        {
            reason = "The administrator part sent a line that is not JSON-RPC: " + e.Message;
        }
        Fail(reason);
    }

    private void Dispatch(string line)
    {
        using var doc = JsonDocument.Parse(line);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object) return;
        if (root.TryGetProperty("id", out var idElement))
        {
            if (idElement.ValueKind != JsonValueKind.Number || !idElement.TryGetUInt64(out var id)
                || !_pending.TryGetValue(id, out var pending))
                return;
            if (root.TryGetProperty("error", out var error)) pending.Fail(ToException(error));
            else if (root.TryGetProperty("result", out var result)) pending.Result.TrySetResult(result.Clone());
            else pending.Fail(new InvalidDataException("a response has neither result nor error"));
            return;
        }
        if (!root.TryGetProperty("method", out var method) || method.ValueKind != JsonValueKind.String) return;
        var name = method.GetString();
        if (string.IsNullOrEmpty(name)) return;
        JsonElement args = root.TryGetProperty("params", out var p) ? p.Clone() : default;
        foreach (var handler in Notification?.GetInvocationList() ?? [])
        {
            try { ((Action<BrokerNotification>)handler)(new BrokerNotification(name, args)); }
            catch (Exception) { }
        }
    }

    private static Exception ToException(JsonElement error)
    {
        ErrorObject? objectError = null;
        try { objectError = error.Deserialize(RpcJsonContext.Default.ErrorObject); }
        catch (JsonException) { }
        var code = objectError?.Code ?? 0;
        var data = objectError?.Data;
        var message = data?.Message ?? objectError?.Message;
        return new BrokerRpcException(code, data?.Kind, message is { Length: > 0 } ? message : "The administrator part reported an error.",
            data);
    }

    private void Fail(string reason)
    {
        _closedReason ??= reason;
        foreach (var pending in _pending.Values) pending.Fail(new BrokerLinkException(reason));
    }

    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
        {
            Fail("The administrator part link was closed.");
            if (_ownsStream)
            {
                try { _stream.Dispose(); }
                catch (IOException) { }
            }
        }
        return ValueTask.CompletedTask;
    }

    private sealed class Pending
    {
        public TaskCompletionSource<JsonElement> Result { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void Fail(Exception e) => Result.TrySetException(e);

        public void Cancel(CancellationToken ct) => Result.TrySetCanceled(ct);
    }
}
