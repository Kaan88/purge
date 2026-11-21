using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using Purge.Client.Model;

namespace Purge.Client.Cli;

/// <summary>
/// The real engine, reached through its CLI: each call runs <c>purge-engine.exe</c> as a child process, reads the
/// document it prints or writes, and maps its exit code to an <see cref="EngineException"/> with a readable
/// message. A stop-gap until the stdio JSON-RPC transport (M3).
/// </summary>
/// <remarks>
/// The engine is <c>purge-engine.exe</c> next to the app, or the file named by <see cref="EngineVar"/>. Scan and
/// exec files go to a work directory under <c>%LOCALAPPDATA%</c> (<see cref="WorkDir"/>). Only a <c>rig-exec</c>
/// or <c>sandbox-dev</c> engine can remove and put back; a normal build answers exit code 5.
/// </remarks>
public sealed class CliEngineClient : IEngineClient
{
    /// <summary>Overrides the engine executable's path.</summary>
    public const string EngineVar = "PURGE_ENGINE_EXE";

    private readonly Lazy<Task<EngineHello>> _hello;

    public CliEngineClient(string? enginePath = null)
    {
        EnginePath = enginePath
                     ?? NonEmpty(Environment.GetEnvironmentVariable(EngineVar))
                     ?? Path.Combine(AppContext.BaseDirectory, "purge-engine.exe");
        _hello = new Lazy<Task<EngineHello>>(() => ReadHelloAsync(CancellationToken.None));
    }

    /// <summary>The engine executable this client runs.</summary>
    public string EnginePath { get; }

    public bool IsLive => true;

    /// <summary>Where scans and exec runs keep their files.</summary>
    public static string WorkDir => Path.Combine(LocalAppData, "PurgeUiTestWork");

    /// <summary>The engine's store: <c>%ProgramData%\Purge</c>.</summary>
    public string StoreRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Purge");

    private static string LocalAppData => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private static string? NonEmpty(string? s) => string.IsNullOrWhiteSpace(s) ? null : s;

    // ---- calls ---------------------------------------------------------------------------------------------

    public Task<EngineHello> HelloAsync(CancellationToken ct = default) => _hello.Value;

    private async Task<EngineHello> ReadHelloAsync(CancellationToken ct)
    {
        var run = await RunAsync("--version", ["--version"], null, ct).ConfigureAwait(false);
        Expect(run, ExitCodes.Ok);
        var (version, canExecute) = EngineDocs.ReadVersion(run.Stdout);
        return new EngineHello(version, Elevated: false, UserSid: "", ShellSid: "", Edition: "", Build: "",
            BaselineAvailable: true, PolicyVersion: "", BuildNote: canExecute ? "rig-exec build" : null);
    }

    public async Task<InventoryDoc> ListProgramsAsync(CancellationToken ct = default)
    {
        var run = await RunAsync("inventory", ["inventory", "--json"], null, ct).ConfigureAwait(false);
        Expect(run, ExitCodes.Ok);
        var doc = JsonSerializer.Deserialize(run.Stdout, PurgeJsonContext.Default.InventoryDoc)
                  ?? throw new InvalidDataException("the engine printed no inventory");
        if (doc.Schema != InventoryDoc.SchemaId)
            throw new InvalidDataException($"unexpected schema {doc.Schema}");
        return doc;
    }

    public bool CanChangePc => true;

    public event Action<IReadOnlyList<Rpc.ProgramPatch>>? ProgramsPatched { add { } remove { } }

    /// <summary>Not measured by the CLI: every program shows "not measured".</summary>
    public Task MeasureSizesAsync(IReadOnlyList<string> programIds, Action<IReadOnlyList<Rpc.ProgramSize>> onBatch, CancellationToken ct = default) =>
        Task.CompletedTask;

    public Task LoadIconsAsync(IReadOnlyList<string> programIds, int px, Action<IReadOnlyList<ProgramIcon>> onBatch, CancellationToken ct = default) =>
        Task.CompletedTask;

    public Task<Rpc.ProgramDetails?> GetProgramAsync(string programId, CancellationToken ct = default) => Task.FromResult<Rpc.ProgramDetails?>(null);

    public Task<Rpc.InventoryChanges> GetInventoryChangesAsync(CancellationToken ct = default) => Task.FromResult(new Rpc.InventoryChanges());

    /// <summary>The CLI test helper lists only; the pipeline is tested with the scripted clients.</summary>
    public Task<Rpc.RouteInfo> GetUninstallRouteAsync(string programId, CancellationToken ct = default) =>
        throw new NotSupportedException("the CLI test helper does not route uninstallers");

    /// <summary>The CLI test helper lists only; the pipeline is tested with the scripted clients.</summary>
    public Task<Rpc.RunUserResult> RunUserUninstallAsync(string programId, bool quiet, Action<Rpc.Progress>? progress = null,
        CancellationToken ct = default) =>
        throw new NotSupportedException("the CLI test helper does not run uninstallers");

    /// <summary>Not in the engine yet: every program stays "not known yet".</summary>
    public Task<IReadOnlyList<LeftoverForecast>> GetForecastsAsync(IReadOnlyList<string> programIds, CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<LeftoverForecast>>([]);

    public async Task<QuarantineStatus> GetQuarantineAsync(CancellationToken ct = default)
    {
        await HelloAsync(ct).ConfigureAwait(false);
        var sessions = Path.Combine(StoreRoot, "sessions");
        var index = ReadShared(Path.Combine(sessions, "index.json"));
        if (index is null) return new QuarantineStatus([], []);
        return EngineDocs.ReadIndex(index, id => ReadShared(Path.Combine(sessions, id, "report.json")), VolumeSize);
    }

    public async Task<LeftoverPlan> ScanAsync(string programId, string programName, ScanKind kind,
        IProgress<EngineProgress>? progress = null, CancellationToken ct = default)
    {
        var dir = NewWorkDir(programName);
        var fp = Path.Combine(dir, "fp.json");
        var plan = Path.Combine(dir, "plan.json");

        progress?.Report(EngineProgress.Step($"Recording {programName}"));
        Expect(await RunAsync("harvest", ["harvest", programId, "-o", fp], progress, ct).ConfigureAwait(false), ExitCodes.Ok);
        if (kind == ScanKind.UninstallThenScan)
        {
            progress?.Report(EngineProgress.Step($"Running the uninstaller of {programName} (quiet)"));
            Expect(await RunAsync("uninstall",
                ["uninstall", programId, "--quiet", "--fp", fp, "-o", Path.Combine(dir, "run.json")], progress, ct)
                .ConfigureAwait(false), ExitCodes.Ok);
        }
        progress?.Report(EngineProgress.Step("Scanning for leftovers"));
        var mode = kind == ScanKind.UninstallThenScan ? "post" : "forced";
        var scan = await RunAsync("scan", ["scan", "--fp", fp, "--mode", mode, "-o", plan], progress, ct).ConfigureAwait(false);
        Expect(scan, ExitCodes.Ok);
        var sidecar = await File.ReadAllTextAsync(Path.Combine(dir, "plan.scan.json"), ct).ConfigureAwait(false);
        return EngineDocs.ReadScan(sidecar, plan, programName, Warnings(scan.Stderr));
    }

    /// <summary>The broker computes the confirm hash in M3; this test helper never executes a plan.</summary>
    public Task<ExecResult> ExecAsync(LeftoverPlan plan, IReadOnlyList<string> selectedIds,
        IProgress<EngineProgress>? progress = null, CancellationToken ct = default) =>
        throw new NotSupportedException("the CLI test helper does not execute plans");

    public async Task<UndoResult> UndoSessionAsync(string sessionId, CancellationToken ct = default)
    {
        var run = await RunAsync("undo", ["undo", "--session", sessionId], null, ct).ConfigureAwait(false);
        Expect(run, ExitCodes.Ok, ExitCodes.Partial, ExitCodes.UndoConflicts, ExitCodes.Unrecorded);
        return EngineDocs.ReadUndo(run.Stdout, run.Code);
    }

    public async Task<IReadOnlyList<PendingSession>> PendingRecoveryAsync(CancellationToken ct = default)
    {
        await HelloAsync(ct).ConfigureAwait(false);
        if (!Directory.Exists(StoreRoot)) return [];
        var run = await RunAsync("journal recover", ["journal", "recover"], null, ct).ConfigureAwait(false);
        Expect(run, ExitCodes.Ok, ExitCodes.StoreIntegrity);
        return EngineDocs.ReadRecover(run.Stdout);
    }

    public async Task<RecoveryResult> RecoverAsync(bool rollback, CancellationToken ct = default)
    {
        var verb = rollback ? "rollback" : "resume";
        var run = await RunAsync("journal " + verb, ["journal", verb], null, ct).ConfigureAwait(false);
        Expect(run, ExitCodes.Ok, ExitCodes.Partial, ExitCodes.UndoConflicts, ExitCodes.StoreIntegrity, ExitCodes.Unrecorded);
        return EngineDocs.ReadRecovered(run.Stdout, run.Code);
    }

    /// <summary>
    /// Ends every engine still running (with what it started) and closes the job, so no engine outlives the app.
    /// Called from the main window's Closed event; later calls fail with <see cref="ObjectDisposedException"/>.
    /// </summary>
    public ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return ValueTask.CompletedTask;
        foreach (var process in _running.Values) KillTree(process);
        _running.Clear();
        _job?.Dispose();
        return ValueTask.CompletedTask;
    }

    // ---- the process ---------------------------------------------------------------------------------------

    /// <summary>How long the output pipes may stay open after the engine exited (a process it started can hold them).</summary>
    public static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(10);

    // Every engine process goes in this job (kill on close) right after it starts, and is tracked until it ends.
    private readonly EngineJob? _job = EngineJob.TryCreate();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<int, Process> _running = new();
    private int _disposed;

    /// <summary>The engine processes running now (tests, diagnostics).</summary>
    public int RunningCount => _running.Count;

    /// <summary>True when the engine processes are put in a kill-on-close job.</summary>
    public bool HasJob => _job is not null;

    /// <summary>One finished engine run.</summary>
    public sealed record Run(string Verb, int Code, string Stdout, string Stderr);

    /// <summary>
    /// Runs the engine with <paramref name="args"/> and waits for it. Stderr lines go to <paramref name="progress"/>
    /// as they come. Cancelling kills the engine (and what it started) and throws <see cref="OperationCanceledException"/>.
    /// After the engine exits its output is read for at most <see cref="DrainTimeout"/>.
    /// </summary>
    public async Task<Run> RunAsync(string verb, IReadOnlyList<string> args, IProgress<EngineProgress>? progress, CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        var psi = new ProcessStartInfo(EnginePath)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        // The engine's timing lines (PURGE_TIMING) are for benchmarks, not for this UI: keep them off.
        psi.Environment.Remove("PURGE_TIMING");
        using var process = new Process { StartInfo = psi };
        try { process.Start(); }
        catch (Win32Exception e)
        {
            throw new EngineException(-1, verb, $"{ExitCodes.Describe(-1, "")} {EnginePath}: {e.Message}", "");
        }
        _job?.Assign(process);
        _running[process.Id] = process;
        try
        {
            process.StandardInput.Close();
            var stdout = new StringBuilder();
            var stdoutDone = Task.Run(async () =>
            {
                var buffer = new char[8192];
                int n;
                while ((n = await process.StandardOutput.ReadAsync(buffer.AsMemory()).ConfigureAwait(false)) > 0)
                    lock (stdout) stdout.Append(buffer, 0, n);
            }, CancellationToken.None);
            var stderr = new StringBuilder();
            var stderrDone = Task.Run(async () =>
            {
                while (await process.StandardError.ReadLineAsync().ConfigureAwait(false) is { } line)
                {
                    lock (stderr) stderr.AppendLine(line);
                    progress?.Report(EngineProgress.Line(line));
                }
            }, CancellationToken.None);
            try { await process.WaitForExitAsync(ct).ConfigureAwait(false); }
            catch (OperationCanceledException)
            {
                KillTree(process);
                throw;
            }
            // The engine has exited; a process it started may still hold the pipes open. Read what is there.
            var drained = await Task.WhenAll(stdoutDone, stderrDone).WaitAsync(DrainTimeout, CancellationToken.None)
                .ContinueWith(t => t.IsCompletedSuccessfully, TaskScheduler.Default).ConfigureAwait(false);
            string text, err;
            lock (stdout) text = stdout.ToString();
            lock (stderr) err = stderr.ToString();
            if (!drained)
                err += $"warning: the engine's output stayed open {DrainTimeout.TotalSeconds:F0} s after it exited; what it printed until then is used{Environment.NewLine}";
            return new Run(verb, process.ExitCode, text, err);
        }
        finally
        {
            _running.TryRemove(process.Id, out _);
        }
    }

    private static void KillTree(Process process)
    {
        try { process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
        catch (Win32Exception) { }
        catch (NotSupportedException) { }
    }

    /// <summary>Throws an <see cref="EngineException"/> unless the run ended with one of <paramref name="accepted"/>.</summary>
    public static void Expect(Run run, params int[] accepted)
    {
        if (accepted.Contains(run.Code)) return;
        throw new EngineException(run.Code, run.Verb,
            ExitCodes.Describe(run.Code, ExitCodes.ErrorLines(run.Stderr)), run.Stderr);
    }

    // ---- helpers -------------------------------------------------------------------------------------------

    private static List<string> Warnings(string stderr) =>
        stderr.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.StartsWith("warning:", StringComparison.Ordinal))
            .Select(l => l["warning:".Length..].Trim())
            .ToList();

    /// <summary>A JSON array of the ids, for <c>--select</c>.</summary>
    public static string IdsJson(IEnumerable<string> ids)
    {
        using var buffer = new MemoryStream();
        using (var w = new Utf8JsonWriter(buffer))
        {
            w.WriteStartArray();
            foreach (var id in ids) w.WriteStringValue(id);
            w.WriteEndArray();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    private static string NewWorkDir(string programName)
    {
        var slug = new string(programName.Select(c => char.IsAsciiLetterOrDigit(c) ? c : '-').ToArray()).Trim('-');
        if (slug.Length > 40) slug = slug[..40];
        var dir = Path.Combine(WorkDir, $"{DateTime.Now:yyyyMMdd-HHmmss}-{(slug.Length > 0 ? slug : "app")}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    /// <summary>A small file read while the engine may hold it: null when it is missing or cannot be read.</summary>
    private static string? ReadShared(string path)
    {
        try
        {
            using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var r = new StreamReader(s, Encoding.UTF8);
            return r.ReadToEnd();
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

    private static long? VolumeSize(string root)
    {
        try { return new DriveInfo(root).TotalSize; }
        catch (Exception e) when (e is IOException or ArgumentException or UnauthorizedAccessException) { return null; }
    }
}
