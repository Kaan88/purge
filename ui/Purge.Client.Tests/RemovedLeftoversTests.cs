using System.IO.Pipes;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;
using Purge.Client.Broker;
using Purge.Client.Pipeline;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// "Check for leftovers" on the Programs page's "removed outside Purge" group (design 7a delta 5): the medium probe of
/// the fingerprint store by the broker's file name, the controller against a scripted launcher and broker (no record
/// means no prompt; a record means <c>leftovers.stored</c> then the stored scan; a cancelled prompt; <c>gone</c>;
/// cancellation), and the wire client's requests. The real broker and the real UAC prompt are VM items.
/// </summary>
public sealed class RemovedLeftoversTests
{
    private const string Program = "HKLM|64|Git_is1";

    // ---- the store's file name and the probe -----------------------------------------------------------------

    [Fact]
    public void The_file_name_is_the_brokers_sha256_of_the_program_id()
    {
        // Pinned outside .NET (sha256sum of the UTF-8 bytes); the broker's test names the same input
        // (bins/purge-broker/src/uninstall.rs, the_names_of_a_write_are_the_patterns_the_store_and_the_sweep_know).
        Assert.Equal("fp-ef2de11f61cd4b09941e0a90a89868d2484d937f5283dc908cab37dff9ace3e1.json",
            FingerprintStore.FileName("HKLM|64|Vendor_is1"));
        Assert.Equal("fp-29f1e50aadd6278b5e6f0b81dc270088f9c08fd161ca7c568dcfce7cda14733a.json",
            FingerprintStore.FileName("HKU:S-1-5-21-1-2-3-1001|64|Café"));
        Assert.EndsWith(Path.Combine("Purge", "fp"), FingerprintStore.DefaultDirectory(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void The_probe_says_no_record_only_when_the_name_or_the_store_is_not_there()
    {
        var root = Path.Combine(Path.GetTempPath(), "purge-fp-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = Path.Combine(root, "fp");
            Assert.False(FingerprintStore.MayHaveRecord(Program, store)); // no fp directory at all
            Directory.CreateDirectory(store);
            Assert.False(FingerprintStore.MayHaveRecord(Program, store));
            File.WriteAllText(Path.Combine(store, FingerprintStore.FileName(Program)), "not read");
            Assert.True(FingerprintStore.MayHaveRecord(Program, store));
            Assert.False(FingerprintStore.MayHaveRecord("HKLM|64|Other", store));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void A_fingerprint_this_process_may_not_read_still_counts_as_a_record()
    {
        if (!OperatingSystem.IsWindows()) return;
        // The real store is admin-only: no entry for Users on fp or its files. An empty protected DACL on both
        // stands in for it; this process stays the owner, so it can give itself access back to clean up.
        var root = Path.Combine(Path.GetTempPath(), "purge-fp-" + Guid.NewGuid().ToString("N"));
        var store = Path.Combine(root, "fp");
        Directory.CreateDirectory(store);
        var file = Path.Combine(store, FingerprintStore.FileName(Program));
        File.WriteAllText(file, "not read");
        var dirInfo = new DirectoryInfo(store);
        var fileInfo = new FileInfo(file);
        var me = System.Security.Principal.WindowsIdentity.GetCurrent().User!;
        try
        {
            var closedFile = new FileSecurity();
            closedFile.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            fileInfo.SetAccessControl(closedFile);
            var closedDir = new DirectorySecurity();
            closedDir.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            dirInfo.SetAccessControl(closedDir);

            Assert.Throws<UnauthorizedAccessException>(() => File.ReadAllText(file));
            Assert.True(FingerprintStore.MayHaveRecord(Program, store));
            Assert.False(FingerprintStore.MayHaveRecord("HKLM|64|Other", store));
        }
        finally
        {
            var openDir = new DirectorySecurity();
            openDir.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
            dirInfo.SetAccessControl(openDir);
            var openFile = new FileSecurity();
            openFile.AddAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl, AccessControlType.Allow));
            fileInfo.SetAccessControl(openFile);
            Directory.Delete(root, recursive: true);
        }
    }

    // ---- the controller -------------------------------------------------------------------------------------

    [Fact]
    public async Task A_program_with_no_record_never_starts_the_broker()
    {
        var launches = 0;
        var controller = new RemovedLeftoversController(_ => false, _ =>
        {
            launches++;
            return Task.FromResult(Started(new ScriptedStoredBroker()));
        });
        controller.Classify([Program]);

        Assert.Equal(RemovedCheckState.NoRecord, controller.StateOf(Program));
        await controller.CheckAsync(Program, "Git").WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(0, launches);
        Assert.Equal(RemovedCheckState.NoRecord, controller.StateOf(Program));
        Assert.Null(controller.Notice);
    }

    [Fact]
    public async Task A_record_asks_stored_then_scans_the_stored_fingerprint_and_hands_the_scan_over()
    {
        var broker = new ScriptedStoredBroker { Stored = [Program], ScanMode = ScanMode.External };
        var controller = new RemovedLeftoversController(_ => true, _ => Task.FromResult(Started(broker)));
        StoredScanOutcome? done = null;
        controller.Completed += o => done = o;
        var states = new List<RemovedCheckState>();
        controller.Changed += () => { lock (states) states.Add(controller.StateOf(Program)); };

        await controller.CheckAsync(Program, "Git").WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(["stored", "scan"], broker.Calls);
        Assert.Equal([Program], broker.StoredAsked);
        Assert.Equal(Program, broker.ScannedProgram);
        Assert.NotNull(done);
        Assert.Equal("s-1", done!.Scan.ScanId);
        Assert.Equal(ScanMode.External, done.Scan.Mode);
        Assert.Equal("Git", done.ProgramName);
        Assert.Contains(RemovedCheckState.Starting, states);
        Assert.Contains(RemovedCheckState.Checking, states);
        Assert.Contains(RemovedCheckState.Scanning, states);
        Assert.Equal(RemovedCheckState.Record, controller.StateOf(Program));
        Assert.True(broker.SessionTaken);
        Assert.True(broker.Disposed);
        Assert.False(controller.IsBusy);
        Assert.Null(controller.Notice);
    }

    [Fact]
    public async Task A_scan_the_broker_turns_forced_reaches_the_leftovers_page_as_forced()
    {
        var broker = new ScriptedStoredBroker { Stored = [Program], ScanMode = ScanMode.Forced };
        var controller = new RemovedLeftoversController(_ => true, _ => Task.FromResult(Started(broker)));
        StoredScanOutcome? done = null;
        controller.Completed += o => done = o;

        await controller.CheckAsync(Program, "Git").WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(ScanMode.Forced, done!.Scan.Mode);
    }

    [Fact]
    public async Task No_stored_record_after_the_prompt_turns_the_row_to_no_record_without_a_scan()
    {
        var broker = new ScriptedStoredBroker { Stored = [] };
        var controller = new RemovedLeftoversController(_ => true, _ => Task.FromResult(Started(broker)));
        var completed = false;
        controller.Completed += _ => completed = true;

        await controller.CheckAsync(Program, "Git").WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(["stored"], broker.Calls);
        Assert.False(completed);
        Assert.True(broker.Disposed);
        Assert.False(broker.SessionTaken);
        Assert.Equal(RemovedCheckState.NoRecord, controller.StateOf(Program));

        // A second click on it does nothing: no prompt for a program without a record.
        var launches = 0;
        var again = new RemovedLeftoversController(_ => false, _ => { launches++; return Task.FromResult(Started(broker)); });
        await again.CheckAsync(Program, "Git");
        await controller.CheckAsync(Program, "Git");
        Assert.Equal(0, launches);
        Assert.Equal(["stored"], broker.Calls);
    }

    [Fact]
    public async Task A_cancelled_prompt_shows_the_cancelled_bar_and_keeps_the_button()
    {
        var controller = new RemovedLeftoversController(_ => true, _ => Task.FromResult(
            new StoredLeftoversLaunch(UninstallLaunchState.Cancelled, null, "You cancelled the admin prompt. Nothing was changed.")));
        var cancelled = 0;
        controller.AdminPromptCancelled += () => cancelled++;
        var completed = false;
        controller.Completed += _ => completed = true;

        await controller.CheckAsync(Program, "Git").WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, cancelled);
        Assert.False(completed);
        Assert.Equal(RemovedCheckState.Record, controller.StateOf(Program));
        Assert.False(controller.IsBusy);
        Assert.Null(controller.Notice); // the shell's bar says it; no second bar
    }

    [Fact]
    public async Task A_launch_that_fails_says_why_and_keeps_the_button()
    {
        var controller = new RemovedLeftoversController(_ => true, _ => Task.FromResult(
            new StoredLeftoversLaunch(UninstallLaunchState.CannotStart, null, "The administrator part could not start.", 22)));

        await controller.CheckAsync(Program, "Git").WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(UninstallNoticeKind.Error, controller.Notice!.Kind);
        Assert.Contains("exit code 22", controller.Notice.Message, StringComparison.Ordinal);
        Assert.Equal(RemovedCheckState.Record, controller.StateOf(Program));
    }

    [Theory]
    [InlineData("stored")]
    [InlineData("scan")]
    public async Task Gone_from_the_broker_means_no_record(string where)
    {
        var broker = new ScriptedStoredBroker { Stored = [Program], GoneAt = where };
        var controller = new RemovedLeftoversController(_ => true, _ => Task.FromResult(Started(broker)));
        var completed = false;
        controller.Completed += _ => completed = true;

        await controller.CheckAsync(Program, "Git").WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(completed);
        Assert.Equal(RemovedCheckState.NoRecord, controller.StateOf(Program));
        Assert.Null(controller.Notice);
        Assert.True(broker.Disposed);
    }

    [Fact]
    public async Task Stop_during_the_scan_cancels_it_and_ends_the_broker()
    {
        var broker = new ScriptedStoredBroker { Stored = [Program], HoldScan = true };
        var controller = new RemovedLeftoversController(_ => true, _ => Task.FromResult(Started(broker)));
        var completed = false;
        controller.Completed += _ => completed = true;

        var check = controller.CheckAsync(Program, "Git");
        await broker.ScanStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(controller.IsBusy);
        Assert.Equal(Program, controller.ActiveProgram);
        Assert.Equal(RemovedCheckState.Scanning, controller.StateOf(Program));
        controller.Cancel();
        await check.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(completed);
        Assert.True(broker.Disposed);
        Assert.False(broker.SessionTaken);
        Assert.Equal(RemovedCheckState.Record, controller.StateOf(Program));
        Assert.Equal(UninstallNoticeKind.Info, controller.Notice!.Kind);
        Assert.False(controller.IsBusy);
    }

    [Fact]
    public async Task A_broker_that_ends_mid_scan_is_an_error_and_keeps_the_button()
    {
        var broker = new ScriptedStoredBroker { Stored = [Program], LinkDiesAtScan = true };
        var controller = new RemovedLeftoversController(_ => true, _ => Task.FromResult(Started(broker)));

        await controller.CheckAsync(Program, "Git").WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(UninstallNoticeKind.Error, controller.Notice!.Kind);
        Assert.Contains("ended", controller.Notice.Title, StringComparison.Ordinal);
        Assert.Equal(RemovedCheckState.Record, controller.StateOf(Program));
    }

    // ---- the wire client ------------------------------------------------------------------------------------

    [Fact]
    public async Task The_session_says_hello_first_then_the_client_asks_stored_and_scans_by_program_id_only()
    {
        await using var peer = await Peer.StartAsync((line, p) =>
        {
            var (id, method) = Peer.RequestOf(line);
            switch (method)
            {
                case "engine.hello":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{ScriptedEngine.HelloResult()}}}");
                    break;
                case "leftovers.stored":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{Fixture("pipe.leftovers.stored.result.json")}}}");
                    break;
                case "leftovers.scan":
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"method\":\"scan.progress\",\"params\":{{\"request\":{id},\"phase\":\"scan\",\"done\":3,\"total\":9}}}}");
                    p.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{Fixture("pipe.leftovers.scan.result.json")}}}");
                    break;
            }
        });
        // The session sends engine.hello when it is made (BrokerSession.OpenAsync); the client sends none of its own.
        await using var session = await BrokerSession.OverAsync(peer.Client);
        await using var client = new StoredLeftoversClient(session);
        var phases = new List<string>();

        var stored = await client.StoredAsync([Program, "HKLM|64|Other"], CancellationToken.None);
        var scan = await client.ScanStoredAsync(Program, p => { lock (phases) phases.Add(p.Phase); }, CancellationToken.None);

        Assert.Equal([Program], stored);
        Assert.Equal("s-0123456789abcdef", scan.ScanId);
        Assert.Equal(["scan"], phases);
        Assert.Same(session, client.TakeSession());
        Assert.Null(client.TakeSession()); // handed over once

        var requests = peer.Requests.Select(line => JsonDocument.Parse(line)).ToList();
        Assert.Equal(["engine.hello", "leftovers.stored", "leftovers.scan"],
            requests.Select(r => r.RootElement.GetProperty("method").GetString()));
        var storedParams = requests[1].RootElement.GetProperty("params");
        Assert.Equal([Program, "HKLM|64|Other"],
            storedParams.GetProperty("program_ids").EnumerateArray().Select(e => e.GetString()));
        var scanParams = requests[2].RootElement.GetProperty("params");
        Assert.Equal(Program, scanParams.GetProperty("program_id").GetString());
        Assert.False(scanParams.TryGetProperty("session_id", out _));
        Assert.False(scanParams.TryGetProperty("forced", out _));
        foreach (var r in requests) r.Dispose();
    }

    // ---- helpers --------------------------------------------------------------------------------------------

    private static StoredLeftoversLaunch Started(IStoredLeftoversBroker broker) =>
        new(UninstallLaunchState.Started, broker, "");

    private static string Fixture(string name) =>
        ScriptedEngine.Compact(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name)));

    /// <summary>A broker that answers <c>leftovers.stored</c> and the stored scan from a script.</summary>
    private sealed class ScriptedStoredBroker : IStoredLeftoversBroker
    {
        public List<string> Stored { get; init; } = [];
        public ScanMode ScanMode { get; init; } = ScanMode.External;
        public string? GoneAt { get; init; }
        public bool HoldScan { get; init; }
        public bool LinkDiesAtScan { get; init; }

        public List<string> Calls { get; } = [];
        public List<string> StoredAsked { get; } = [];
        public string? ScannedProgram { get; private set; }
        public bool SessionTaken { get; private set; }
        public bool Disposed { get; private set; }
        public TaskCompletionSource ScanStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<IReadOnlyList<string>> StoredAsync(IReadOnlyList<string> programIds, CancellationToken ct)
        {
            Calls.Add("stored");
            StoredAsked.AddRange(programIds);
            if (GoneAt == "stored") throw new BrokerRpcException(-32000, "gone", "gone: program");
            return Task.FromResult<IReadOnlyList<string>>(programIds.Where(Stored.Contains).ToList());
        }

        public async Task<ScanResult> ScanStoredAsync(string programId, Action<Progress>? progress, CancellationToken ct)
        {
            Calls.Add("scan");
            ScannedProgram = programId;
            ScanStarted.TrySetResult();
            if (GoneAt == "scan") throw new BrokerRpcException(-32000, "gone", "gone: program");
            if (LinkDiesAtScan) throw new BrokerLinkException("The administrator part closed the link.");
            progress?.Invoke(new Progress { Phase = "scan", Done = 1 });
            if (HoldScan) await Task.Delay(Timeout.Infinite, ct);
            return new ScanResult { ScanId = "s-1", Mode = ScanMode, Counts = new BandCounts() };
        }

        public BrokerSession? TakeSession()
        {
            SessionTaken = true;
            return null;
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    /// <summary>A broker played by this test process over a real pipe: request lines in, JSON lines out.</summary>
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
            var name = "purge-removed-" + Guid.NewGuid().ToString("N");
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
            return (root.GetProperty("id").GetUInt64(), root.GetProperty("method").GetString() ?? "");
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
