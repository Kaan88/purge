using System.Diagnostics;
using System.Text.Json;
using Purge.Client.Model;
using Purge.Client.Stdio;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>The stdio client against an engine played by the test, and against a real child process.</summary>
public sealed class StdioEngineClientTests
{
    [Fact]
    public async Task HelloAndListFollowTheWireFormat()
    {
        using var engine = ScriptedEngine.Healthy();
        await using var client = engine.Client;

        var hello = await client.HelloAsync();
        Assert.Equal("0.1.0", hello.Version);
        Assert.False(hello.Elevated);
        Assert.Equal("Professional", hello.Edition);
        Assert.Equal("26100.9711", hello.Build);
        Assert.Equal("S-1-5-21-1-2-3-1001", hello.UserSid);
        Assert.Equal(hello.UserSid, hello.ShellSid);
        Assert.Equal("bl.1", hello.PolicyVersion);
        Assert.True(hello.BaselineAvailable);

        var doc = await client.ListProgramsAsync();
        var git = Assert.Single(doc.Entries);
        Assert.Equal("HKLM|64|Git_is1", git.ProgramId);
        Assert.Equal("Git", git.DisplayName);
        Assert.Equal("2.47.0", git.Version);
        Assert.Equal("The Git Development Community", git.Publisher);
        Assert.Equal(InstallScope.Machine, git.Scope);
        Assert.Equal(RegistryView.K64, git.View);
        Assert.Equal(@"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1", git.KeyPath);
        Assert.Equal(134076753020000000UL, git.InstallTimeEvidence![0].Time);

        lock (engine.Requests)
        {
            Assert.Equal(2, engine.Requests.Count);
            Assert.All(engine.Requests, l => Assert.Equal("2.0", JsonDocument.Parse(l).RootElement.GetProperty("jsonrpc").GetString()));
            Assert.Equal(["engine.hello", "programs.list"], engine.Requests.Select(ScriptedEngine.MethodOf));
            Assert.Equal([1UL, 2UL], engine.Requests.Select(ScriptedEngine.IdOf));
        }
    }

    [Fact]
    public async Task RowsMayArriveBeforeTheReplyThatCountsThem()
    {
        using var engine = new ScriptedEngine((line, e) =>
        {
            var id = ScriptedEngine.IdOf(line);
            e.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"programs.batch\",\"params\":{ScriptedEngine.BatchParams(id)}}}");
            e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"count\":1}}}}");
        });
        await using var client = engine.Client;
        Assert.Single((await client.ListProgramsAsync()).Entries);
    }

    [Fact]
    public async Task WaitsForTheRowsTheReplyPromised()
    {
        using var engine = new ScriptedEngine((line, e) =>
            e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{ScriptedEngine.IdOf(line)},\"result\":{{\"count\":1}}}}"));
        await using var client = engine.Client;
        var list = client.ListProgramsAsync();
        await Task.Delay(150);
        Assert.False(list.IsCompleted);
        engine.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"programs.batch\",\"params\":{ScriptedEngine.BatchParams(1)}}}");
        Assert.Single((await list).Entries);
    }

    [Fact]
    public async Task AnErrorResponseNamesItsKind()
    {
        using var engine = new ScriptedEngine((line, e) =>
            e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{ScriptedEngine.IdOf(line)},\"error\":{ScriptedEngine.Compact(ScriptedEngine.Sample("stdio.error.runtime.json"))}}}"));
        await using var client = engine.Client;
        var error = await Assert.ThrowsAsync<EngineRpcException>(() => client.HelloAsync());
        Assert.Equal("runtime", error.Kind);
        Assert.Equal(-32000, error.Code);
        Assert.Equal("the harvest store could not be opened", error.Message);
    }

    [Fact]
    public async Task AnEngineThatEndsFailsTheOpenRequest()
    {
        using var engine = new ScriptedEngine((_, e) => e.End());
        await using var client = engine.Client;
        var error = await Assert.ThrowsAsync<EngineLinkException>(() => client.HelloAsync());
        Assert.Contains("ended", error.Message);
        // Later calls fail at once instead of waiting for a reply that cannot come.
        await Assert.ThrowsAsync<EngineLinkException>(() => client.HelloAsync());
    }

    [Fact]
    public async Task CancellingSendsCancelAndEndsTheCall()
    {
        using var engine = new ScriptedEngine();
        await using var client = engine.Client;
        using var cts = new CancellationTokenSource();
        var list = client.ListProgramsAsync(cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => list);
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < deadline)
        {
            lock (engine.Requests)
                if (engine.Requests.Count == 2) break;
            await Task.Delay(20);
        }
        lock (engine.Requests)
        {
            using var cancel = JsonDocument.Parse(engine.Requests[1]);
            Assert.Equal("$/cancel", cancel.RootElement.GetProperty("method").GetString());
            Assert.Equal(1UL, cancel.RootElement.GetProperty("params").GetProperty("request").GetUInt64());
            Assert.False(cancel.RootElement.TryGetProperty("id", out _));
        }
    }

    [Fact]
    public void AMissingEngineFileIsReported()
    {
        var path = Path.Combine(Path.GetTempPath(), "purge-no-such-engine", "purge-engine.exe");
        var error = Assert.Throws<FileNotFoundException>(() => StdioEngineClient.Start(path));
        Assert.Contains("purge-engine.exe", error.Message);
    }

    [Fact]
    public async Task AChildProcessTalksOverInheritedPipesAndDiesWithItsJob()
    {
        var dir = Path.Combine(Path.GetTempPath(), "purge-stdio-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var pidFile = Path.Combine(dir, "pid.txt");
            var script = Path.Combine(dir, "engine.ps1");
            // A stand-in engine: writes its pid, answers hello and programs.list from stdin to stdout.
            File.WriteAllText(script, $$$"""
                [IO.File]::WriteAllText('{{{pidFile}}}', [string]$PID)
                $out = [Console]::Out
                while ($true) {
                  $l = [Console]::In.ReadLine()
                  if ($null -eq $l) { break }
                  $id = [regex]::Match($l, '"id":(\d+)').Groups[1].Value
                  if ($l -match 'engine.hello') {
                    $out.WriteLine('{"jsonrpc":"2.0","id":' + $id + ',"result":{{{ScriptedEngine.HelloResult()}}}}')
                  } elseif ($l -match 'programs.list') {
                    $out.WriteLine('{"jsonrpc":"2.0","id":' + $id + ',"result":{"count":1}}')
                    $p = '{{{ScriptedEngine.BatchParams(0)}}}'.Replace('"request":0', '"request":' + $id)
                    $out.WriteLine('{"jsonrpc":"2.0","method":"programs.batch","params":' + $p + '}')
                  }
                  $out.Flush()
                }
                """);
            var powershell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
            var client = StdioEngineClient.Start(powershell, $"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"{script}\"");
            try
            {
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(60));
                Assert.Equal("0.1.0", (await client.HelloAsync(cts.Token)).Version);
                Assert.Single((await client.ListProgramsAsync(cts.Token)).Entries);
            }
            finally
            {
                await client.DisposeAsync();
            }

            var pid = int.Parse(File.ReadAllText(pidFile).Trim());
            var deadline = DateTime.UtcNow.AddSeconds(10);
            while (IsRunning(pid) && DateTime.UtcNow < deadline) await Task.Delay(50);
            Assert.False(IsRunning(pid), "closing the client must end the engine through its kill-on-close job");
        }
        finally
        {
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
    }

    private static bool IsRunning(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
