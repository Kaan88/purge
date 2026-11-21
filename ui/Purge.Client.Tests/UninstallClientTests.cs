using System.Text.Json;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using Purge.Client.Stdio;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The medium engine's uninstall methods over the stdio link (M3-RUNNER): <c>uninstall.route</c>,
/// <c>uninstall.run_user</c> with its <c>uninstall.progress</c> notifications, its <c>wrong_route</c> refusal and a link
/// that dies mid-run. The real engine and a real uninstaller are VM items.
/// </summary>
public sealed class UninstallClientTests
{
    private static string Reply(ulong id, string result) => $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{result}}}";

    [Fact]
    public async Task Route_reads_the_fixture_and_sends_the_program_id()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            if (ScriptedEngine.MethodOf(line) != "uninstall.route") return;
            e.Send(Reply(ScriptedEngine.IdOf(line),
                ScriptedEngine.Compact(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "stdio.uninstall.route.result.json")))));
        });
        await using var client = engine.Client;

        var route = await client.GetUninstallRouteAsync("HKU:S-1-5-21-1-2-3-1001|64|VSCodeUserSetup");

        Assert.Equal(Route.Medium, route.Route);
        Assert.Equal(@"""C:\Users\u\AppData\Local\Programs\Microsoft VS Code\unins000.exe""", route.Command);
        Assert.Equal(@"""C:\Users\u\AppData\Local\Programs\Microsoft VS Code\unins000.exe"" /VERYSILENT", route.QuietCommand);
        Assert.Equal("Microsoft Corporation", route.Signer);
        Assert.Equal("Code.exe", Assert.Single(route.Running).Name);
        Assert.Equal(4242U, route.Running[0].Pid);

        using var request = JsonDocument.Parse(Assert.Single(engine.Requests));
        Assert.Equal("uninstall.route", request.RootElement.GetProperty("method").GetString());
        Assert.Equal("HKU:S-1-5-21-1-2-3-1001|64|VSCodeUserSetup",
            request.RootElement.GetProperty("params").GetProperty("program_id").GetString());
    }

    [Fact]
    public async Task Run_user_sends_quiet_reports_each_progress_line_and_returns_the_result()
    {
        var phases = new List<string>();
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            if (ScriptedEngine.MethodOf(line) != "uninstall.run_user") return;
            foreach (var phase in new[] { "record", "wait", "exit" })
                e.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"uninstall.progress\",\"params\":{{\"request\":{id}," +
                       $"\"program_id\":\"HKU:S-1-5-21-1-2-3-1001|64|App\",\"phase\":\"{phase}\",\"done\":1,\"total\":null}}}}");
            e.Send(Reply(id, ScriptedEngine.Compact(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "stdio.uninstall.run_user.result.json")))));
        });
        await using var client = engine.Client;

        var result = await client.RunUserUninstallAsync("HKU:S-1-5-21-1-2-3-1001|64|App", quiet: true,
            progress => { lock (phases) phases.Add(progress.Phase); });

        Assert.Equal(0U, result.ExitCode);
        Assert.Equal(RunOutcome.Success, result.Outcome);
        Assert.Equal(["record", "wait", "exit"], phases);

        using var request = JsonDocument.Parse(Assert.Single(engine.Requests));
        Assert.Equal("uninstall.run_user", request.RootElement.GetProperty("method").GetString());
        var parameters = request.RootElement.GetProperty("params");
        Assert.Equal("HKU:S-1-5-21-1-2-3-1001|64|App", parameters.GetProperty("program_id").GetString());
        Assert.True(parameters.GetProperty("quiet").GetBoolean());
    }

    [Fact]
    public async Task Run_user_refusal_names_wrong_route_and_keeps_the_link()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            if (ScriptedEngine.MethodOf(line) == "uninstall.run_user")
                e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{ScriptedEngine.IdOf(line)},\"error\":{ScriptedEngine.Compact(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "error.wrong_route.json")))}}}");
            else e.Send(Reply(ScriptedEngine.IdOf(line), ScriptedEngine.HelloResult()));
        });
        await using var client = engine.Client;

        var error = await Assert.ThrowsAsync<EngineRpcException>(() => client.RunUserUninstallAsync("HKLM|64|Git", quiet: true));
        Assert.Equal("wrong_route", error.Kind);
        // The link stays: another request still goes out.
        Assert.Equal("0.1.0", (await client.HelloAsync()).Version);
    }

    [Fact]
    public async Task An_engine_that_dies_during_run_user_fails_the_call_with_the_link_error()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            if (ScriptedEngine.MethodOf(line) == "uninstall.run_user") e.End();
        });
        await using var client = engine.Client;

        var error = await Assert.ThrowsAsync<EngineLinkException>(() => client.RunUserUninstallAsync("HKLM|64|App", quiet: true));
        Assert.Contains("engin", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A_broker_uninstall_failed_keeps_its_exit_code_and_forced_offer()
    {
        // The broker client parses error.data whole, so the page can offer the forced cleanup with the code.
        var peer = await ScriptedBrokerPeer.StartAsync((line, pipe) =>
        {
            var (id, method) = ScriptedBrokerPeer.RequestOf(line);
            if (method != "uninstall.run") return;
            pipe.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{ScriptedEngine.Compact(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "error.uninstall_failed.json")))}}}");
        });
        await using var rpc = BrokerRpcClient.Over(peer.Client, ownsStream: true);
        using var parameters = JsonDocument.Parse("{\"session_id\":\"u-1122334455667788\",\"quiet\":true}");

        var error = await Assert.ThrowsAsync<BrokerRpcException>(() =>
            rpc.CallAsync("uninstall.run", parameters.RootElement));

        Assert.Equal("uninstall_failed", error.Kind);
        Assert.Equal(1603U, error.Details?.ExitCode);
        Assert.True(error.Details?.ForcedOffered);
    }

    /// <summary>A broker played by this test process: request lines in, JSON lines out.</summary>
    private sealed class ScriptedBrokerPeer : IAsyncDisposable
    {
        private readonly System.IO.Pipes.NamedPipeServerStream _server;
        private readonly System.IO.Pipes.NamedPipeClientStream _client;
        private readonly StreamWriter _writer;
        private readonly Task _loop;

        private ScriptedBrokerPeer(System.IO.Pipes.NamedPipeServerStream server,
            System.IO.Pipes.NamedPipeClientStream client, Action<string, ScriptedBrokerPeer> onLine)
        {
            _server = server;
            _client = client;
            _writer = new StreamWriter(server, new System.Text.UTF8Encoding(false)) { AutoFlush = true };
            _loop = Task.Run(() => Loop(onLine));
        }

        public System.IO.Pipes.NamedPipeClientStream Client => _client;

        public static async Task<ScriptedBrokerPeer> StartAsync(Action<string, ScriptedBrokerPeer> onLine)
        {
            var name = "purge-s2-" + Guid.NewGuid().ToString("N");
            var server = new System.IO.Pipes.NamedPipeServerStream(name, System.IO.Pipes.PipeDirection.InOut, 1,
                System.IO.Pipes.PipeTransmissionMode.Byte, System.IO.Pipes.PipeOptions.Asynchronous);
            var client = new System.IO.Pipes.NamedPipeClientStream(".", name, System.IO.Pipes.PipeDirection.InOut,
                System.IO.Pipes.PipeOptions.Asynchronous);
            var connected = server.WaitForConnectionAsync();
            await client.ConnectAsync(5000);
            await connected;
            return new ScriptedBrokerPeer(server, client, onLine);
        }

        public void Send(string line)
        {
            lock (_writer) _writer.WriteLine(line);
        }

        private void Loop(Action<string, ScriptedBrokerPeer> onLine)
        {
            try
            {
                using var reader = new StreamReader(_server);
                while (reader.ReadLine() is { } line) onLine(line, this);
            }
            catch (Exception e) when (e is IOException or ObjectDisposedException or InvalidOperationException) { }
        }

        public static (ulong Id, string Method) RequestOf(string line)
        {
            using var doc = JsonDocument.Parse(line);
            return (doc.RootElement.GetProperty("id").GetUInt64(), doc.RootElement.GetProperty("method").GetString() ?? "");
        }

        public async ValueTask DisposeAsync()
        {
            try { _client.Dispose(); } catch (IOException) { }
            try { _server.Dispose(); } catch (IOException) { }
            try { await _loop.WaitAsync(TimeSpan.FromSeconds(5)); } catch (Exception e) when (e is TimeoutException or AggregateException or IOException) { }
            try { _writer.Dispose(); } catch (ObjectDisposedException) { }
        }
    }
}
