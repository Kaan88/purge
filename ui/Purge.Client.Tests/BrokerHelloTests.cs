using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Purge.Client.Broker;
using Purge.Client.Pipeline;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The broker serves nothing before <c>engine.hello</c>: it drops a client whose first line is anything else
/// (<c>bins/purge-broker/src/serve.rs</c>, <c>accept</c>). A <see cref="BrokerSession"/> is made only after the hello
/// was answered (<c>BrokerSession.OpenAsync</c>, which the launcher's connect and <c>BrokerSession.OverAsync</c> both
/// use), so every client over a session works against such a broker without sending a hello of its own. These tests
/// play that broker over a real pipe and drive each client the UI builds on a session: History &amp; undo and the
/// Quarantine vault (<see cref="HistoryBroker"/>), the Uninstall pipeline, the removed-program check and the Leftovers
/// page.
/// </summary>
public sealed class BrokerHelloTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(10);

    [Fact]
    public async Task A_link_whose_first_request_is_not_hello_is_dropped_by_the_scripted_broker()
    {
        // The control: the peer behaves as the broker does.
        await using var peer = await HelloFirstPeer.StartAsync();
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);

        await Assert.ThrowsAsync<BrokerLinkException>(() =>
            rpc.CallAsync("history.get", new SessionParams { Session = "u-1122334455667788" },
                RpcJsonContext.Default.SessionParams, RpcJsonContext.Default.HistoryDetail).WaitAsync(Limit));
        Assert.True(peer.Refused);
    }

    [Fact]
    public async Task History_calls_reach_a_broker_that_wants_hello_first()
    {
        await using var peer = await HelloFirstPeer.StartAsync();
        var session = await BrokerSession.OverAsync(peer.Client).WaitAsync(Limit);
        await using IHistoryBroker history = new HistoryBroker(session);

        await history.GetAsync("u-1122334455667788", CancellationToken.None).WaitAsync(Limit);
        await history.PendingAsync(CancellationToken.None).WaitAsync(Limit);
        await history.RecoverAsync("u-1122334455667788", rollback: false, CancellationToken.None).WaitAsync(Limit);
        await history.RecoverAsync("u-1122334455667788", rollback: true, CancellationToken.None).WaitAsync(Limit);
        await history.UndoAsync("u-1122334455667788", [1, 2], null, CancellationToken.None).WaitAsync(Limit);

        Assert.False(peer.Refused);
        Assert.Equal(["engine.hello", "history.get", "journal.pending", "journal.resume", "journal.rollback", "undo.run"],
            peer.Methods);
        Assert.False(string.IsNullOrEmpty(session.Hello.Version));
    }

    [Fact]
    public async Task Vault_calls_reach_a_broker_that_wants_hello_first()
    {
        await using var peer = await HelloFirstPeer.StartAsync();
        var session = await BrokerSession.OverAsync(peer.Client).WaitAsync(Limit);
        await using IVaultBroker vault = new HistoryBroker(session);

        var expiring = await vault.ExpiringAsync(CancellationToken.None).WaitAsync(Limit);
        await vault.PurgeAsync(["x-1"], CancellationToken.None).WaitAsync(Limit);
        await vault.UndoAsync("u-1122334455667788", null, null, CancellationToken.None).WaitAsync(Limit);

        Assert.NotNull(expiring);
        Assert.False(peer.Refused);
        Assert.Equal(["engine.hello", "quarantine.expiring", "quarantine.purge", "undo.run"], peer.Methods);
    }

    [Fact]
    public async Task The_uninstall_check_and_leftovers_clients_send_no_hello_of_their_own()
    {
        await using var peer = await HelloFirstPeer.StartAsync();
        await using var session = await BrokerSession.OverAsync(peer.Client).WaitAsync(Limit);

        var uninstall = new BrokerUninstallClient(session);
        await uninstall.PrepareAsync(["HKLM|64|Git_is1"], null, CancellationToken.None).WaitAsync(Limit);
        Assert.Same(session, uninstall.TakeSession());
        await uninstall.DisposeAsync();

        var stored = new StoredLeftoversClient(session);
        await stored.StoredAsync(["HKLM|64|Git_is1"], CancellationToken.None).WaitAsync(Limit);
        await stored.ScanStoredAsync("HKLM|64|Git_is1", null, CancellationToken.None).WaitAsync(Limit);
        Assert.Same(session, stored.TakeSession());
        await stored.DisposeAsync();

        var leftovers = new LeftoversBroker(session.Rpc);
        await leftovers.CandidatesAsync("s-0123456789abcdef", 0, 100, CancellationToken.None).WaitAsync(Limit);

        Assert.False(peer.Refused);
        Assert.Equal(["engine.hello", "uninstall.prepare", "leftovers.stored", "leftovers.scan", "scan.candidates"],
            peer.Methods);
    }

    [Fact]
    public async Task A_refused_or_dropped_hello_makes_no_session()
    {
        await using (var refusing = await HelloFirstPeer.StartAsync(refuseHello: true))
        {
            await Assert.ThrowsAsync<BrokerRpcException>(() => BrokerSession.OverAsync(refusing.Client).WaitAsync(Limit));
        }
        await using (var dropping = await HelloFirstPeer.StartAsync(dropAtHello: true))
        {
            await Assert.ThrowsAsync<BrokerLinkException>(() => BrokerSession.OverAsync(dropping.Client).WaitAsync(Limit));
        }
    }

    /// <summary>
    /// A broker played over a real pipe that, like <c>serve.rs</c>, drops a client whose first line is not
    /// <c>engine.hello</c>; after the hello it answers each method with its recorded pipe fixture.
    /// </summary>
    private sealed class HelloFirstPeer : IAsyncDisposable
    {
        private readonly NamedPipeServerStream _server;
        private readonly NamedPipeClientStream _client;
        private readonly StreamWriter _writer;
        private readonly List<string> _methods = [];
        private readonly bool _refuseHello;
        private readonly bool _dropAtHello;
        private readonly Task _loop;
        private volatile bool _refused;

        private HelloFirstPeer(NamedPipeServerStream server, NamedPipeClientStream client, bool refuseHello, bool dropAtHello)
        {
            _server = server;
            _client = client;
            _refuseHello = refuseHello;
            _dropAtHello = dropAtHello;
            _writer = new StreamWriter(server, new UTF8Encoding(false)) { AutoFlush = true };
            _loop = Task.Run(Loop);
        }

        public NamedPipeClientStream Client => _client;

        /// <summary>True once a first line that was not <c>engine.hello</c> made it drop the client.</summary>
        public bool Refused => _refused;

        public List<string> Methods
        {
            get { lock (_methods) return [.. _methods]; }
        }

        public static async Task<HelloFirstPeer> StartAsync(bool refuseHello = false, bool dropAtHello = false)
        {
            var name = "purge-hello-" + Guid.NewGuid().ToString("N");
            var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            var connected = server.WaitForConnectionAsync();
            await client.ConnectAsync(5000);
            await connected;
            return new HelloFirstPeer(server, client, refuseHello, dropAtHello);
        }

        private void Loop()
        {
            try
            {
                using var reader = new StreamReader(_server, new UTF8Encoding(false));
                var first = true;
                while (reader.ReadLine() is { } line)
                {
                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    var method = root.GetProperty("method").GetString() ?? "";
                    if (method == "$/cancel") continue;
                    var id = root.GetProperty("id").GetUInt64();
                    lock (_methods) _methods.Add(method);
                    if (first)
                    {
                        first = false;
                        if (method != "engine.hello")
                        {
                            _refused = true;
                            _server.Disconnect();
                            return;
                        }
                        if (_dropAtHello)
                        {
                            _server.Disconnect();
                            return;
                        }
                        if (_refuseHello)
                        {
                            Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":-32000,\"message\":\"refused\",\"data\":{{\"kind\":\"runtime\",\"message\":\"refused\"}}}}}}");
                            continue;
                        }
                    }
                    var fixture = Path.Combine(AppContext.BaseDirectory, "Fixtures", $"pipe.{method}.result.json");
                    Send(File.Exists(fixture)
                        ? $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{ScriptedEngine.Compact(File.ReadAllText(fixture))}}}"
                        : $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":-32601,\"message\":\"no fixture for {method}\"}}}}");
                }
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException or InvalidOperationException)
            {
            }
        }

        private void Send(string line)
        {
            lock (_writer) _writer.WriteLine(line);
        }

        public async ValueTask DisposeAsync()
        {
            try { _client.Dispose(); }
            catch (IOException) { }
            try { _server.Dispose(); }
            catch (IOException) { }
            try { await _loop.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception e) when (e is IOException or TimeoutException or ObjectDisposedException or AggregateException) { }
            try { _writer.Dispose(); }
            catch (ObjectDisposedException) { }
        }
    }
}
