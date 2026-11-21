using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
using Purge.Client.Broker;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// Review M3-R2 B2: the client's pipe handle must allow a write while the reader thread is inside a read. The
/// broker sends nothing before <c>engine.hello</c>, so a write that waits for the read never ends. These tests open
/// the pipe through <see cref="BrokerPipe.TryOpen"/> (the code the launcher uses) against (1) the real Rust broker
/// pipe server, run unelevated by the <c>pipe_harness</c> example, and (2) an in-process server that stays inside
/// a pending read and sends nothing until it has the hello line.
/// </summary>
public sealed class BrokerPipeTests
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(5);

    private static string Image => Environment.ProcessPath ?? throw new InvalidOperationException("no process path");

    [Fact]
    public async Task HelloCompletesAgainstTheRealBrokerPipeServer()
    {
        using var harness = await Harness.StartAsync();
        using var open = BrokerPipe.TryOpen(harness.PipePath, harness.Process.Id, harness.ExePath, requireElevation: false);
        Assert.Null(open.Check);
        Assert.NotNull(open.Stream);

        await using var rpc = BrokerRpcClient.Over(open.TakeStream(), ownsStream: true);
        // The reader is already blocked in a read; the real broker sends nothing until it has the hello. The call runs on\n        // a pool thread because the request is written synchronously: a deadlocked write must fail this test, not hang it.
        await Task.Delay(300);
        var hello = await Task.Run(() => rpc.HelloAsync()).WaitAsync(Limit);
        Assert.Equal("0.1.0", hello.Version);
        Assert.True(rpc.IsLive);
        Assert.False(harness.Process.HasExited, "the broker pipe server must still be serving the client");
    }

    [Fact]
    public async Task AFailedServerCheckOnTheRealPipeOpensNoStream()
    {
        using var harness = await Harness.StartAsync();
        using var open = BrokerPipe.TryOpen(harness.PipePath, harness.Process.Id + 4, harness.ExePath, requireElevation: false);
        Assert.NotNull(open.Check);
        Assert.Equal(BrokerServerCheckStatus.PidMismatch, open.Check.Status);
        Assert.Null(open.Stream);
    }

    [Fact]
    public async Task HelloCompletesWhileTheServerStaysInAPendingRead()
    {
        var name = "purge-b2-" + Guid.NewGuid().ToString("N");
        await using var server = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
        var served = Task.Run(async () =>
        {
            await server.WaitForConnectionAsync();
            // Nothing is sent first, like the broker: the line below arrives only if the client could write.
            var buffer = new byte[4096];
            var read = 0;
            while (read == 0 || buffer[read - 1] != (byte)'\n')
                read += await server.ReadAsync(buffer.AsMemory(read));
            using var doc = System.Text.Json.JsonDocument.Parse(Encoding.UTF8.GetString(buffer, 0, read));
            var id = doc.RootElement.GetProperty("id").GetUInt64();
            var answer = $"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{ScriptedEngine.HelloResult()}}}\n";
            await server.WriteAsync(Encoding.UTF8.GetBytes(answer));
            await server.FlushAsync();
        });

        var path = @"\\.\pipe\" + name;
        using var open = BrokerPipe.TryOpen(path, Environment.ProcessId, Image, requireElevation: false);
        Assert.Null(open.Check);
        var stream = open.TakeStream();
        Assert.True(stream.IsAsync, "the client handle must be opened overlapped");

        await using var rpc = BrokerRpcClient.Over(stream, ownsStream: true);
        await Task.Delay(300);
        var hello = await Task.Run(() => rpc.HelloAsync()).WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Equal("0.1.0", hello.Version);
        await served.WaitAsync(Limit);
    }

    /// <summary>The real broker pipe server (<c>cargo build -p purge-broker --example pipe_harness</c>), unelevated, expecting this process as its client.</summary>
    private sealed class Harness : IDisposable
    {
        private static readonly Lazy<string> Exe = new(Build);

        private Harness(Process process, string exePath, string pipePath)
        {
            Process = process;
            ExePath = exePath;
            PipePath = pipePath;
        }

        public Process Process { get; }

        public string ExePath { get; }

        public string PipePath { get; }

        public static async Task<Harness> StartAsync()
        {
            var exe = Exe.Value;
            var self = Process.GetCurrentProcess();
            var info = new ProcessStartInfo(exe)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            info.ArgumentList.Add(Guid.NewGuid().ToString("N"));
            info.ArgumentList.Add(Environment.ProcessId.ToString());
            info.ArgumentList.Add(self.StartTime.ToFileTimeUtc().ToString());
            info.ArgumentList.Add(Image);
            var process = Process.Start(info) ?? throw new InvalidOperationException("pipe_harness did not start");
            try
            {
                var line = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(20));
                if (line is null || !line.StartsWith("READY ", StringComparison.Ordinal))
                    throw new InvalidOperationException("pipe_harness: " + (line ?? process.StandardError.ReadToEnd()));
                return new Harness(process, exe, line["READY ".Length..]);
            }
            catch
            {
                Kill(process);
                throw;
            }
        }

        public void Dispose() => Kill(Process);

        private static void Kill(Process process)
        {
            try { if (!process.HasExited) process.Kill(); }
            catch (InvalidOperationException) { }
            process.Dispose();
        }

        private static string Build()
        {
            var root = AppContext.BaseDirectory;
            while (root is not null && !File.Exists(Path.Combine(root, "Cargo.toml"))) root = Path.GetDirectoryName(root);
            if (root is null) throw new InvalidOperationException("the repository root (Cargo.toml) was not found");
            var build = new ProcessStartInfo("cargo", "build -q -p purge-broker --example pipe_harness")
            {
                WorkingDirectory = root,
                UseShellExecute = false,
                RedirectStandardError = true,
            };
            using var cargo = Process.Start(build) ?? throw new InvalidOperationException("cargo did not start");
            var errors = cargo.StandardError.ReadToEndAsync();
            if (!cargo.WaitForExit(TimeSpan.FromMinutes(10))) { cargo.Kill(); throw new TimeoutException("cargo build timed out"); }
            if (cargo.ExitCode != 0) throw new InvalidOperationException("cargo build failed: " + errors.Result);
            var target = Environment.GetEnvironmentVariable("CARGO_TARGET_DIR") ?? Path.Combine(root, "target");
            var exe = Path.Combine(target, "debug", "examples", "pipe_harness.exe");
            return File.Exists(exe) ? exe : throw new FileNotFoundException(exe);
        }
    }
}