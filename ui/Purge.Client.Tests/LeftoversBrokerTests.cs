using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The Leftovers page's broker wrapper: the exact method names and params of design 6.3, the
/// <c>consent.shown</c> notification and the <c>plan_refused</c> refusals. The real broker is a VM test.
/// </summary>
public sealed class LeftoversBrokerTests
{
    [Fact]
    public async Task TheWrapperSendsTheDesignParamsAndReadsConsentAndRefusals()
    {
        await using var peer = await Peer.StartAsync((line, p) =>
        {
            var (id, method) = Peer.RequestOf(line);
            switch (method)
            {
                case "leftovers.scan":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"scan_id\":\"scan-1\",\"mode\":\"forced\"," +
                           "\"counts\":{\"safe\":1,\"likely\":0,\"weak\":0,\"blocked\":0,\"preselected\":1}," +
                           "\"baseline_trust\":\"Exact\",\"warnings\":[]}}");
                    break;
                case "scan.candidates":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"total\":1,\"offset\":0,\"items\":[" +
                           "{\"candidate_id\":\"c-0000000000000001\",\"band\":\"Safe\",\"kind\":\"file\"," +
                           "\"category\":\"AppFiles\",\"display_name\":\"C:\\\\Temp\\\\a\",\"preselected\":true," +
                           "\"warnings\":[]}]}}");
                    break;
                case "plan.create":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":-32000,\"message\":\"refused\"," +
                           "\"data\":{\"kind\":\"plan_refused\",\"refusals\":[{\"candidate_id\":\"c-0000000000000001\"," +
                           "\"reason\":\"cannot back it up\"}]}}}");
                    break;
                case "plan.execute":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"consent.shown\",\"params\":{{\"request\":{id},\"code\":\"A1B2-C3D4\"}}}}");
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"outcome\":\"complete\",\"session\":\"sess-1\"," +
                           "\"counts\":{\"done\":1,\"vanished\":0},\"held\":[]," +
                           "\"restore_point\":{\"kind\":\"Created\",\"sequence\":7}}}");
                    break;
                case "undo.run":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"consent.shown\",\"params\":{{\"request\":{id},\"code\":\"E5F6-A7B8\"}}}}");
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"outcome\":\"complete\",\"conflicts\":[]}}}}");
                    break;
                case "journal.retry_held":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"outcome\":\"partial\"}}}}");
                    break;
            }
        });
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        var broker = new LeftoversBroker(rpc);
        var codes = new List<string>();
        broker.ConsentShown += shown => codes.Add(shown.Code);

        var scan = await broker.ScanSessionAsync("us-1", forced: true, progress: null, CancellationToken.None);
        Assert.Equal("scan-1", scan.ScanId);
        Assert.Equal(ScanMode.Forced, scan.Mode);

        var page = await broker.CandidatesAsync("scan-1", 0, 500, CancellationToken.None);
        Assert.Equal("c-0000000000000001", Assert.Single(page.Items).CandidateId);

        var refused = await Assert.ThrowsAsync<BrokerRpcException>(() =>
            broker.CreatePlanAsync("scan-1", ["c-0000000000000001"], CancellationToken.None));
        Assert.Equal("plan_refused", refused.Kind);
        var refusal = Assert.Single(refused.Details!.Refusals!);
        Assert.Equal("c-0000000000000001", refusal.CandidateId);
        Assert.Equal("cannot back it up", refusal.Reason);

        var result = await broker.ExecuteAsync("p-1", RestorePoint.HighRisk, null, CancellationToken.None);
        Assert.Equal(Outcome.Complete, result.Outcome);
        Assert.Equal(7, result.RestorePoint.Sequence);

        _ = await broker.UndoAsync("sess-1", null, CancellationToken.None);
        _ = await broker.RetryHeldAsync("sess-1", CancellationToken.None);
        Assert.Equal(new[] { "A1B2-C3D4", "E5F6-A7B8" }, codes);

        var requests = peer.Requests;
        Assert.Contains("\"session_id\":\"us-1\"", requests.Single(r => r.Contains("\"leftovers.scan\"", StringComparison.Ordinal)));
        Assert.Contains("\"forced\":true", requests.Single(r => r.Contains("\"leftovers.scan\"", StringComparison.Ordinal)));
        Assert.Contains("\"offset\":0", requests.Single(r => r.Contains("\"scan.candidates\"", StringComparison.Ordinal)));
        Assert.Contains("\"scan_id\":\"scan-1\"", requests.Single(r => r.Contains("\"plan.create\"", StringComparison.Ordinal)));
        Assert.Contains("\"restore_point\":\"high_risk\"", requests.Single(r => r.Contains("\"plan.execute\"", StringComparison.Ordinal)));
        Assert.Contains("\"session\":\"sess-1\"", requests.Single(r => r.Contains("\"undo.run\"", StringComparison.Ordinal)));
        Assert.Contains("\"session\":\"sess-1\"", requests.Single(r => r.Contains("\"journal.retry_held\"", StringComparison.Ordinal)));
    }

    /// <summary>
    /// "Delete instead of keeping in quarantine" on the wire (DECISIONS 2026-11-24): the same <c>plan.execute</c> with
    /// <c>delete_after: true</c> and nothing else new (no item, no path, no id); the plain call says <c>false</c>.
    /// The two prompts announce two codes, the phase of the delete step is forwarded, and the answer's
    /// <c>delete_after</c> is read; an answer without it reads as null.
    /// </summary>
    [Fact]
    public async Task DeleteAfterIsOneFlagOnPlanExecuteAndItsAnswerIsRead()
    {
        await using var peer = await Peer.StartAsync((line, p) =>
        {
            var (id, method) = Peer.RequestOf(line);
            if (method != "plan.execute") return;
            var asked = line.Contains("\"delete_after\":true", StringComparison.Ordinal);
            p.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"consent.shown\",\"params\":{{\"request\":{id},\"code\":\"A1B2-C3D4\"}}}}");
            if (asked)
            {
                p.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"exec.progress\",\"params\":{{\"request\":{id},\"phase\":\"delete_after\",\"done\":1,\"total\":1}}}}");
                p.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"consent.shown\",\"params\":{{\"request\":{id},\"code\":\"E5F6-A7B8\"}}}}");
            }
            p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"outcome\":\"complete\",\"session\":\"sess-1\"," +
                   "\"counts\":{\"done\":2,\"vanished\":0},\"held\":[],\"restore_point\":{\"kind\":\"NotRequested\"}" +
                   (asked ? ",\"delete_after\":{\"outcome\":\"partial\",\"purged\":1,\"kept\":1}" : "") + "}}");
        });
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        var foreground = 0;
        var broker = new LeftoversBroker(rpc) { AllowForeground = () => Interlocked.Increment(ref foreground) };
        var codes = new List<string>();
        broker.ConsentShown += shown => { lock (codes) codes.Add(shown.Code); };
        var phases = new List<string>();
        var progress = new ListProgress(phases);

        var plain = await broker.ExecuteAsync("p-1", RestorePoint.Off, progress, CancellationToken.None);
        Assert.Null(plain.DeleteAfter);
        Assert.Equal(0, foreground);

        var result = await broker.ExecuteThenDeleteAsync("p-2", RestorePoint.HighRisk, progress, CancellationToken.None);
        Assert.Equal(Outcome.Complete, result.Outcome);
        Assert.NotNull(result.DeleteAfter);
        Assert.Equal(DeleteAfterOutcome.Partial, result.DeleteAfter!.Outcome);
        Assert.Equal((1u, 1u), (result.DeleteAfter.Purged, result.DeleteAfter.Kept));
        Assert.Equal(["delete_after"], phases);
        // The broker was allowed the foreground when its delete step was announced, from the reader thread.
        Assert.Equal(1, foreground);
        Assert.Equal(["A1B2-C3D4", "A1B2-C3D4", "E5F6-A7B8"], codes);

        var requests = peer.Requests;
        Assert.Contains("\"params\":{\"delete_after\":false,\"plan_id\":\"p-1\",\"restore_point\":\"off\"}", requests[0]);
        Assert.Contains("\"params\":{\"delete_after\":true,\"plan_id\":\"p-2\",\"restore_point\":\"high_risk\"}", requests[1]);
    }

    /// <summary>A progress sink that records the phases as they arrive (no synchronization context in between).</summary>
    private sealed class ListProgress(List<string> phases) : IProgress<Progress>
    {
        public void Report(Progress value)
        {
            lock (phases) phases.Add(value.Phase);
        }
    }

    /// <summary>
    /// The broker's optional <c>timings</c> member (design 9.1, gate G12) is read when present, a mark name or member
    /// the client does not know changes nothing, and a result without it reads as before (null).
    /// </summary>
    [Fact]
    public async Task TheTimingsMemberIsReadWhenPresentAndIgnoredWhenAbsent()
    {
        const string timings = ",\"timings\":{\"process_created_unix_ms\":1795000000000,\"later\":1,\"marks\":[" +
                               "{\"mark\":\"pipe_connected\",\"ms\":180,\"wall_unix_ms\":1795000000180}," +
                               "{\"mark\":\"scan_start\",\"ms\":9020,\"wall_unix_ms\":1795000009020}," +
                               "{\"mark\":\"a_mark_of_a_later_broker\",\"ms\":9030,\"wall_unix_ms\":1795000009030}," +
                               "{\"mark\":\"scan_complete\",\"ms\":12310,\"wall_unix_ms\":1795000012310}]}";
        await using var peer = await Peer.StartAsync((line, p) =>
        {
            var (id, method) = Peer.RequestOf(line);
            var withTimings = line.Contains("\"forced\":true", StringComparison.Ordinal);
            switch (method)
            {
                case "leftovers.scan":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"scan_id\":\"scan-1\",\"mode\":\"forced\"," +
                           "\"counts\":{\"safe\":1,\"likely\":0,\"weak\":0,\"blocked\":0,\"preselected\":1}," +
                           "\"baseline_trust\":\"Exact\",\"warnings\":[]" + (withTimings ? timings : "") + "}}");
                    break;
                case "plan.execute":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"outcome\":\"complete\",\"session\":\"sess-1\"," +
                           "\"counts\":{\"done\":1,\"vanished\":0},\"held\":[]," +
                           "\"restore_point\":{\"kind\":\"Created\",\"sequence\":7}" + timings + "}}");
                    break;
            }
        });
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        var broker = new LeftoversBroker(rpc);

        var timed = await broker.ScanSessionAsync("us-1", forced: true, progress: null, CancellationToken.None);
        Assert.Equal("scan-1", timed.ScanId);
        Assert.NotNull(timed.Timings);
        Assert.Equal(1795000000000UL, timed.Timings!.ProcessCreatedUnixMs);
        Assert.Equal(["pipe_connected", "scan_start", "a_mark_of_a_later_broker", "scan_complete"],
            timed.Timings.Marks.Select(m => m.Mark));
        Assert.Equal(12310UL - 9020UL, timed.Timings.Marks[3].Ms - timed.Timings.Marks[1].Ms);

        var plain = await broker.ScanSessionAsync("us-1", forced: false, progress: null, CancellationToken.None);
        Assert.Equal("scan-1", plain.ScanId);
        Assert.Equal(ScanMode.Forced, plain.Mode);
        Assert.Null(plain.Timings);

        var result = await broker.ExecuteAsync("p-1", RestorePoint.Off, null, CancellationToken.None);
        Assert.Equal(Outcome.Complete, result.Outcome);
        Assert.Equal(4, result.Timings!.Marks.Count);

        // Read and written back, an absent member stays absent.
        var (_, scanResult) = RpcFixtures.All.Single(f => f.Stem == "pipe.leftovers.scan.result");
        var written = scanResult("{\"scan_id\":\"scan-1\",\"mode\":\"forced\",\"counts\":{\"safe\":1,\"likely\":0," +
                                 "\"weak\":0,\"blocked\":0,\"preselected\":1},\"baseline_trust\":\"Exact\",\"warnings\":[]}");
        Assert.DoesNotContain("timings", written, StringComparison.Ordinal);
    }

    private sealed class Peer : IAsyncDisposable
    {
        private readonly NamedPipeServerStream _server;
        private readonly NamedPipeClientStream _client;
        private readonly StreamWriter _writer;
        private readonly List<string> _requests = [];
        private readonly Task _loop;

        private Peer(NamedPipeServerStream server, NamedPipeClientStream client, Action<string, Peer> onLine)
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

        public static async Task<Peer> StartAsync(Action<string, Peer> onLine)
        {
            var name = "purge-leftovers-" + Guid.NewGuid().ToString("N");
            var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var client = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            var connected = server.WaitForConnectionAsync();
            await client.ConnectAsync(5000);
            await connected;
            return new Peer(server, client, onLine);
        }

        public void Send(string line)
        {
            lock (_writer) _writer.WriteLine(line);
        }

        private void Loop(Action<string, Peer> onLine)
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
            try { _server.Dispose(); }
            catch (IOException) { }
            try { await _loop.WaitAsync(TimeSpan.FromSeconds(5)); }
            catch (Exception e) when (e is IOException or TimeoutException or ObjectDisposedException or AggregateException) { }
            try { _writer.Dispose(); }
            catch (ObjectDisposedException) { }
        }
    }
}
