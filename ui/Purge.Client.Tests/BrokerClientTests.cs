using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The broker link: framing round trips, notifications, cancel, errors, a server that ends, the server check on a
/// pipe served by this test process, and the error-1223 mapping. The real elevated broker is a VM test.
/// </summary>
public sealed class BrokerClientTests
{
    [Fact]
    public async Task FramingRoundTripReadsTheResultAndNotifications()
    {
        var notified = new TaskCompletionSource<BrokerNotification>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var peer = await PipePeer.StartAsync((line, pipe) =>
        {
            var (id, method) = PipePeer.RequestOf(line);
            switch (method)
            {
                case "engine.hello":
                    pipe.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{ScriptedEngine.HelloResult()}}}");
                    pipe.Send("{\"jsonrpc\":\"2.0\",\"method\":\"baseline.changed\",\"params\":{\"state\":\"working\"}}");
                    break;
                case "broker.shutdown":
                    pipe.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"exiting\":true}}}}");
                    break;
            }
        });
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        rpc.Notification += n => notified.TrySetResult(n);

        var hello = await rpc.HelloAsync();
        Assert.Equal("0.1.0", hello.Version);
        Assert.False(hello.Elevated);
        var notification = await notified.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("baseline.changed", notification.Method);
        Assert.Equal("working", notification.Params.GetProperty("state").GetString());

        var shutdown = await rpc.ShutdownAsync();
        Assert.True(shutdown.Exiting);

        var requests = peer.Requests;
        Assert.Equal(2, requests.Count);
        using (var helloLine = JsonDocument.Parse(requests[0]))
        {
            var root = helloLine.RootElement;
            Assert.Equal("2.0", root.GetProperty("jsonrpc").GetString());
            Assert.Equal(1UL, root.GetProperty("id").GetUInt64());
            Assert.Equal("engine.hello", root.GetProperty("method").GetString());
            Assert.False(root.TryGetProperty("params", out _));
        }
        using (var shutdownLine = JsonDocument.Parse(requests[1]))
        {
            Assert.Equal(2UL, shutdownLine.RootElement.GetProperty("id").GetUInt64());
            Assert.Equal("broker.shutdown", shutdownLine.RootElement.GetProperty("method").GetString());
        }
        Assert.True(rpc.IsLive);
    }

    [Fact]
    public async Task CancellingSendsCancelAndEndsTheCall()
    {
        var cancelled = new TaskCompletionSource<ulong>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var peer = await PipePeer.StartAsync((line, pipe) =>
        {
            var (id, method) = PipePeer.RequestOf(line);
            if (method == "$/cancel")
            {
                cancelled.TrySetResult(JsonDocument.Parse(line).RootElement.GetProperty("params").GetProperty("request").GetUInt64());
                return;
            }
            if (method == "leftovers.scan") return; // never answers
            pipe.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{}}}}");
        });
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        using var cts = new CancellationTokenSource();
        var call = rpc.CallAsync("leftovers.scan", JsonDocument.Parse("{\"session_id\":\"1\"}").RootElement, cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
        Assert.Equal(1UL, await cancelled.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.True(rpc.IsLive, "cancelling one request does not end the link");
    }

    [Fact]
    public async Task AnErrorResponseNamesItsKind()
    {
        await using var peer = await PipePeer.StartAsync((line, pipe) =>
        {
            var (id, _) = PipePeer.RequestOf(line);
            pipe.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":-32000,"
                      + "\"message\":\"the request failed\",\"data\":{\"kind\":\"runtime\",\"message\":\"the harvest store could not be opened\"}}}");
        });
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        var error = await Assert.ThrowsAsync<BrokerRpcException>(() => rpc.HelloAsync());
        Assert.Equal(-32000, error.Code);
        Assert.Equal("runtime", error.Kind);
        Assert.Equal("the harvest store could not be opened", error.Message);
    }

    [Fact]
    public async Task AServerThatEndsFailsTheOpenRequest()
    {
        await using var peer = await PipePeer.StartAsync((_, pipe) => pipe.End());
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        var error = await Assert.ThrowsAsync<BrokerLinkException>(() => rpc.HelloAsync());
        Assert.Contains("ended", error.Message);
        Assert.False(rpc.IsLive);
        // Later calls fail at once instead of waiting for a reply that cannot come.
        await Assert.ThrowsAsync<BrokerLinkException>(() => rpc.HelloAsync());
    }

    [Fact]
    public async Task ServerCheckRefusesAPipeServedByAnotherProcess()
    {
        var (server, client) = await ConnectPipeAsync();
        using (server)
        using (client)
        {
            var image = Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "Purge.Client.Tests.exe");
            var otherPid = BrokerServerCheck.Check(client.SafePipeHandle, Environment.ProcessId + 1, image,
                requireElevation: false);
            Assert.Equal(BrokerServerCheckStatus.PidMismatch, otherPid.Status);
            Assert.Contains("not the administrator part", otherPid.Reason);

            var otherImage = BrokerServerCheck.Check(client.SafePipeHandle, Environment.ProcessId, image + ".other",
                requireElevation: false);
            Assert.Equal(BrokerServerCheckStatus.ImageMismatch, otherImage.Status);

            var own = BrokerServerCheck.Check(client.SafePipeHandle, Environment.ProcessId, image,
                requireElevation: false);
            Assert.Equal(BrokerServerCheckStatus.Ok, own.Status);
        }
    }

    [Fact]
    public void CancelledUacMapsToTheCancelledResult()
    {
        var cancelled = BrokerLauncher.ClassifyShellFailure(1223);
        Assert.Equal(BrokerLaunchStatus.Cancelled, cancelled.Status);
        Assert.Null(cancelled.Session);
        Assert.Contains("cancelled", cancelled.Message, StringComparison.OrdinalIgnoreCase);

        var failed = BrokerLauncher.ClassifyShellFailure(5);
        Assert.Equal(BrokerLaunchStatus.CannotStart, failed.Status);
        Assert.Equal(5, failed.Win32Error);
    }

    private static async Task<(NamedPipeServerStream Server, NamedPipeClientStream Client)> ConnectPipeAsync()
    {
        var name = "purge-test-" + Guid.NewGuid().ToString("N");
        var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        var connected = server.WaitForConnectionAsync();
        await client.ConnectAsync(5000);
        await connected;
        return (server, client);
    }

    /// <summary>A broker played by this test process: one pipe instance, request lines in, JSON lines out.</summary>
    private sealed class PipePeer : IAsyncDisposable
    {
        private readonly NamedPipeServerStream _server;
        private readonly NamedPipeClientStream _client;
        private readonly StreamWriter _writer;
        private readonly List<string> _requests = [];
        private readonly Task _loop;

        private PipePeer(NamedPipeServerStream server, NamedPipeClientStream client, Action<string, PipePeer> onLine)
        {
            _server = server;
            _client = client;
            _writer = new StreamWriter(server, new UTF8Encoding(false)) { AutoFlush = true };
            _loop = Task.Run(() => Loop(onLine));
        }

        public NamedPipeClientStream Client => _client;

        public List<string> Requests
        {
            get { lock (_requests) return [.. _requests]; }
        }

        public static async Task<PipePeer> StartAsync(Action<string, PipePeer> onLine)
        {
            var (server, client) = await ConnectPipeAsync();
            return new PipePeer(server, client, onLine);
        }

        public void Send(string line)
        {
            lock (_writer) _writer.WriteLine(line);
        }

        /// <summary>Ends the server end: the client's reader sees the end of the stream.</summary>
        public void End()
        {
            try { _server.Dispose(); }
            catch (IOException) { }
        }

        private void Loop(Action<string, PipePeer> onLine)
        {
            try
            {
                using var reader = new StreamReader(_server, new UTF8Encoding(false));
                while (reader.ReadLine() is { } line)
                {
                    lock (_requests) _requests.Add(line);
                    onLine(line, this);
                }
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException or InvalidOperationException)
            {
            }
        }

        public static (ulong Id, string Method) RequestOf(string line)
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            var method = root.GetProperty("method").GetString() ?? "";
            var id = root.TryGetProperty("id", out var idElement) ? idElement.GetUInt64() : 0;
            return (id, method);
        }

        public async ValueTask DisposeAsync()
        {
            try { _client.Dispose(); }
            catch (IOException) { }
            End();
            try { await _loop.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception e) when (e is IOException or TimeoutException or ObjectDisposedException or AggregateException) { }
            try { _writer.Dispose(); }
            catch (ObjectDisposedException) { }
        }
    }
}
