using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Purge.Client.Stdio;

namespace Purge.Client.Tests;

/// <summary>An engine played by a test: reads the client's request lines and answers through <see cref="Send"/>.</summary>
internal sealed class ScriptedEngine : IDisposable
{
    private readonly AnonymousPipeServerStream _toEngine = new(PipeDirection.Out);
    private readonly AnonymousPipeServerStream _fromEngine = new(PipeDirection.Out);
    private readonly object _gate = new();

    /// <param name="onLine">Called for every request line; answers with <see cref="Send"/>. Null: never answers.</param>
    public ScriptedEngine(Action<string, ScriptedEngine>? onLine = null)
    {
        var engineIn = new AnonymousPipeClientStream(PipeDirection.In, _toEngine.ClientSafePipeHandle);
        var clientIn = new AnonymousPipeClientStream(PipeDirection.In, _fromEngine.ClientSafePipeHandle);
        Client = StdioEngineClient.Over(_toEngine, clientIn);
        Task.Run(() =>
        {
            using var reader = new StreamReader(engineIn);
            while (reader.ReadLine() is { } line)
            {
                lock (Requests) Requests.Add(line);
                onLine?.Invoke(line, this);
            }
        });
    }

    public StdioEngineClient Client { get; }

    public List<string> Requests { get; } = [];

    public void Send(string line)
    {
        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        lock (_gate)
        {
            _fromEngine.Write(bytes);
            _fromEngine.Flush();
        }
    }

    /// <summary>The engine ends: the client's reader sees the end of the stream.</summary>
    public void End() => _fromEngine.Dispose();

    public static ulong IdOf(string requestLine) => JsonDocument.Parse(requestLine).RootElement.GetProperty("id").GetUInt64();

    public static string MethodOf(string requestLine) => JsonDocument.Parse(requestLine).RootElement.GetProperty("method").GetString()!;

    public static string Sample(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", name));

    /// <summary>The recorded fixture of the engine's <c>engine.hello</c> result, one line.</summary>
    public static string HelloResult() => Compact(Sample("stdio.engine.hello.result.json"));

    /// <summary>The recorded <c>programs.batch</c> params with <paramref name="request"/> as its request id.</summary>
    public static string BatchParams(ulong request)
    {
        using var doc = JsonDocument.Parse(Sample("stdio.programs.batch.json"));
        return $"{{\"request\":{request},\"rows\":{JsonSerializer.Serialize(doc.RootElement.GetProperty("rows"))}}}";
    }

    public static string Compact(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return JsonSerializer.Serialize(doc.RootElement);
    }

    /// <summary>The healthy engine: answers hello, then <c>programs.list</c> with a batch and the count.</summary>
    public static ScriptedEngine Healthy() => new((line, engine) =>
    {
        var id = IdOf(line);
        switch (MethodOf(line))
        {
            case "engine.hello":
                engine.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{HelloResult()}}}");
                break;
            case "programs.list":
                engine.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"count\":1}}}}");
                engine.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"programs.batch\",\"params\":{BatchParams(id)}}}");
                break;
        }
    });

    public void Dispose()
    {
        _toEngine.Dispose();
        _fromEngine.Dispose();
    }
}
