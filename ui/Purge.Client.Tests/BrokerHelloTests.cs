using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
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

        var expiring = await vault.ExpiringAsync(false, CancellationToken.None).WaitAsync(Limit);
        await vault.PurgeAsync(["x-1"], CancellationToken.None).WaitAsync(Limit);
        await vault.UndoAsync("u-1122334455667788", null, null, CancellationToken.None).WaitAsync(Limit);

        Assert.NotNull(expiring);
        Assert.False(peer.Refused);
        Assert.Equal(["engine.hello", "quarantine.expiring", "quarantine.purge", "undo.run"], peer.Methods);
    }

    /// <summary>
    /// "Delete now" on the wire: the listing asks for the items that are not due with <c>include_not_due</c>, and the
    /// delete is <c>quarantine.purge</c> with the broker's ids and nothing else (no path, no "early" word of the
    /// client's: the broker reads that from its own listing).
    /// </summary>
    [Fact]
    public async Task Delete_now_asks_for_the_items_that_are_not_due_and_names_only_ids()
    {
        await using var peer = await HelloFirstPeer.StartAsync();
        var session = await BrokerSession.OverAsync(peer.Client).WaitAsync(Limit);
        await using IVaultBroker vault = new HistoryBroker(session);

        var all = await vault.ExpiringAsync(true, CancellationToken.None).WaitAsync(Limit);
        await vault.ExpiringAsync(false, CancellationToken.None).WaitAsync(Limit);
        await vault.PurgeAsync([all.Items[0].ExpiryId], CancellationToken.None).WaitAsync(Limit);
        // "Also delete its registry backups": the same two calls; only the listing asks for more, the delete still
        // names ids and nothing else (the broker reads from its own listing that an id is a backup that is not due).
        await vault.ExpiringWithBackupsAsync(CancellationToken.None).WaitAsync(Limit);
        await vault.PurgeAsync([all.Items[0].ExpiryId], CancellationToken.None).WaitAsync(Limit);

        Assert.True(all.Items[0].Due);
        Assert.Equal(
            [
                ("quarantine.expiring", "{\"include_backups_not_due\":false,\"include_not_due\":true}"),
                ("quarantine.expiring", "{\"include_backups_not_due\":false,\"include_not_due\":false}"),
                ("quarantine.purge", "{\"expiry_ids\":[\"e-0e0e000000000007\"]}"),
                ("quarantine.expiring", "{\"include_backups_not_due\":true,\"include_not_due\":true}"),
                ("quarantine.purge", "{\"expiry_ids\":[\"e-0e0e000000000007\"]}"),
            ],
            peer.Requests.Skip(1));
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

    /// <summary>The launcher's handshake (<c>BrokerLauncher.HandshakeAsync</c>) against the scripted broker.</summary>
    private static async Task<(BrokerLaunchResult Result, int Terminated)> HandshakeAsync(HelloFirstPeer peer,
        TimeSpan helloTimeout, CancellationToken ct = default)
    {
        var terminated = 0;
        var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        var result = await BrokerLauncher.HandshakeAsync(rpc, new SafeProcessHandle(0, ownsHandle: false),
            Environment.ProcessId, "", helloTimeout, ct, _ => Interlocked.Increment(ref terminated)).WaitAsync(Limit);
        return (result, terminated);
    }

    [Fact]
    public async Task The_handshake_makes_a_session_once_hello_is_answered()
    {
        await using var peer = await HelloFirstPeer.StartAsync();
        var (result, terminated) = await HandshakeAsync(peer, Limit);

        Assert.Equal(BrokerLaunchStatus.Started, result.Status);
        Assert.NotNull(result.Session);
        Assert.Equal(0, terminated);
        await result.Session!.DisposeAsync();
    }

    [Fact]
    public async Task A_refused_or_dropped_hello_is_cannot_start_and_ends_the_process()
    {
        await using (var refusing = await HelloFirstPeer.StartAsync(refuseHello: true))
        {
            var (result, terminated) = await HandshakeAsync(refusing, Limit);
            Assert.Equal(BrokerLaunchStatus.CannotStart, result.Status);
            Assert.Null(result.Session);
            Assert.Contains("did not accept", result.Message, StringComparison.Ordinal);
            Assert.Equal(1, terminated);
        }
        await using (var dropping = await HelloFirstPeer.StartAsync(dropAtHello: true))
        {
            var (result, terminated) = await HandshakeAsync(dropping, Limit);
            Assert.Equal(BrokerLaunchStatus.CannotStart, result.Status);
            Assert.Null(result.Session);
            Assert.Equal(1, terminated);
        }
    }

    [Fact]
    public async Task A_hello_never_answered_is_timed_out_and_ends_the_process()
    {
        await using var peer = await HelloFirstPeer.StartAsync(silentAtHello: true);
        var (result, terminated) = await HandshakeAsync(peer, TimeSpan.FromMilliseconds(200));

        Assert.Equal(BrokerLaunchStatus.TimedOut, result.Status);
        Assert.Null(result.Session);
        Assert.Contains("did not answer", result.Message, StringComparison.Ordinal);
        Assert.Equal(1, terminated);
        Assert.Equal(["engine.hello"], peer.Methods);
    }

    [Fact]
    public async Task The_callers_cancellation_is_rethrown_and_ends_the_process()
    {
        await using var peer = await HelloFirstPeer.StartAsync(silentAtHello: true);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var terminated = 0;
        var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => BrokerLauncher.HandshakeAsync(rpc,
            new SafeProcessHandle(0, ownsHandle: false), Environment.ProcessId, "", Limit, cts.Token,
            _ => Interlocked.Increment(ref terminated)).WaitAsync(Limit));
        Assert.Equal(1, terminated);
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
        private readonly List<(string Method, string Params)> _requests = [];
        private readonly bool _refuseHello;
        private readonly bool _dropAtHello;
        private readonly bool _silentAtHello;
        private readonly Task _loop;
        private volatile bool _refused;

        private HelloFirstPeer(NamedPipeServerStream server, NamedPipeClientStream client, bool refuseHello, bool dropAtHello,
            bool silentAtHello)
        {
            _server = server;
            _client = client;
            _refuseHello = refuseHello;
            _dropAtHello = dropAtHello;
            _silentAtHello = silentAtHello;
            _writer = new StreamWriter(server, new UTF8Encoding(false)) { AutoFlush = true };
            // Its own thread: the loop blocks in ReadLine, and the pool is shared with every test running at once
            // (the timeout tests count on the client's timer, not on a free pool thread).
            _loop = Task.Factory.StartNew(Loop, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public NamedPipeClientStream Client => _client;

        /// <summary>True once a first line that was not <c>engine.hello</c> made it drop the client.</summary>
        public bool Refused => _refused;

        public List<string> Methods
        {
            get { lock (_methods) return [.. _methods]; }
        }

        /// <summary>Every request with its params as sent (<c>""</c> when it had none).</summary>
        public List<(string Method, string Params)> Requests
        {
            get { lock (_methods) return [.. _requests]; }
        }

        /// <param name="silentAtHello">Reads the hello and never answers it (the link stays open).</param>
        public static async Task<HelloFirstPeer> StartAsync(bool refuseHello = false, bool dropAtHello = false,
            bool silentAtHello = false)
        {
            var name = "purge-hello-" + Guid.NewGuid().ToString("N");
            var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            var connected = server.WaitForConnectionAsync();
            await client.ConnectAsync(5000);
            await connected;
            return new HelloFirstPeer(server, client, refuseHello, dropAtHello, silentAtHello);
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
                    var sent = root.TryGetProperty("params", out var p) ? p.GetRawText() : "";
                    lock (_methods)
                    {
                        _methods.Add(method);
                        _requests.Add((method, sent));
                    }
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
                        if (_silentAtHello) continue;
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
