using Purge.Client.Cli;
using Purge.Client.Model;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The engine's documents as the client reads them. The samples in Samples\ are real engine output: rig-* from
/// the sandbox-dev round trip test (bins/purge-engine/tests/exec_cli.rs, PURGE_SBX_DUMP_DIR), npp-* a cut of a
/// read-only scan; user paths and SIDs are replaced.
/// </summary>
public sealed class EngineDocsTests
{
    private static string Sample(string name) => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Samples", name));

    [Fact]
    public void ScanSidecarOfTheRig()
    {
        var plan = EngineDocs.ReadScan(Sample("rig-plan.scan.json"), @"C:\w\plan.json", "Rig", ["w1"]);
        Assert.Equal("942f107d3b6f83672a3545ea4025f1a3e3def2ab022403beaefdf1a99737e27a", plan.PlanHash);
        Assert.Equal("rig-targets", plan.App);
        Assert.Equal("post", plan.Mode);
        Assert.Equal(@"C:\w\plan.json", plan.PlanPath);
        Assert.Equal(["w1"], plan.Warnings);
        Assert.Equal(["files.dir", "single"], plan.Items.Select(i => i.Id));
        var first = plan.Items[0];
        Assert.Equal(LeftoverBand.Safe, first.Band);
        Assert.True(first.Preselected);
        Assert.True(first.Selectable);
        Assert.True(first.IsFile);
        Assert.Equal("AppFiles", first.Category);
        Assert.Equal("Quarantine", first.Action);
        Assert.EndsWith(@"\work\app", first.Display);
        Assert.Null(first.SizeBytes);
    }

    [Fact]
    public void ScanSidecarOfARealScan()
    {
        var plan = EngineDocs.ReadScan(Sample("npp-plan.scan.json"), "p.json", "Notepad++", []);
        Assert.Equal("external", plan.Mode);
        Assert.Equal(5, plan.Items.Count);
        var blocked = plan.Items.Single(i => i.Id == "c-214f2c4121a1bc65");
        Assert.Equal(LeftoverBand.Blocked, blocked.Band);
        Assert.False(blocked.Selectable);
        Assert.False(blocked.Preselected);
        Assert.EndsWith(@"Programs\Notepad++.lnk", blocked.Display);
        var folder = plan.Items.Single(i => i.Id == "c-5788caac5780cea9");
        Assert.True(folder.IsFile && folder.Selectable);
        Assert.Equal(LeftoverBand.Likely, folder.Band);

        var byType = plan.Items.Where(i => i.TargetType != "Path").ToDictionary(i => i.TargetType);

        var value = byType["RegValue"];
        Assert.Equal(LeftoverBand.Likely, value.Band);
        Assert.True(value.IsRegistry && value.Selectable);
        Assert.EndsWith(@"\OpenWithList [a]", value.Display);
        Assert.StartsWith("Refers to notepad++.exe", value.Explanation);
        Assert.Equal(1, value.Evidence);

        Assert.EndsWith(@"\OpenWithList [MRUList] : a", byType["RegMultiSzSegment"].Display);
        Assert.StartsWith("RegMultiSzSegment: ", byType["RegMultiSzSegment"].Display);
        Assert.EndsWith(@"App Paths\notepad++.exe", byType["RegKey"].Display);
    }

    [Fact]
    public void WrongSchemaOrNotJsonIsRefused()
    {
        Assert.Throws<InvalidDataException>(() => EngineDocs.ReadScan(Sample("rig-report.json"), "p", "x", []));
        Assert.Throws<InvalidDataException>(() => EngineDocs.ReadExec("not json", 0));
        Assert.Throws<InvalidDataException>(() => EngineDocs.ReadUndo("{}", 0));
    }

    [Fact]
    public void ExecReport()
    {
        var r = EngineDocs.ReadExec(Sample("rig-report.json"), 0);
        Assert.Equal("20261115T223530Z-cada70265f85311e", r.SessionId);
        Assert.Equal("Committed", r.State);
        Assert.Equal(2, r.Done);
        Assert.Equal(0, r.Failed + r.Skipped + r.HeldRetry + r.PendingReboot + r.Vanished);
        Assert.Equal(11, r.BackupBytes);
        Assert.Equal(["files.dir", "single"], r.Items.Select(i => i.Id));
        Assert.All(r.Items, i => Assert.True(i.Complete));
        Assert.Equal("Done", r.Items[0].Outcome);
    }

    [Fact]
    public void ExecOutcomesWithReasons()
    {
        const string json = """
            { "schema": "purge.exec/1", "session": "s", "state": "Committed",
              "items": [
                { "item": "a", "target": { "type": "Path", "path": "C:\\a" }, "outcome": { "kind": "Skipped", "reason": "ChangedSinceScan" } },
                { "item": "b", "target": { "type": "Path", "path": "C:\\b" }, "outcome": { "kind": "Failed", "code": "AccessDenied", "os_error": 5, "detail": "locked" } },
                { "item": "c", "target": { "type": "RegKey", "path": "HKCU\\X" }, "outcome": { "kind": "Skipped", "reason": "NoLongerEmpty" } } ],
              "counts": { "done": 0, "vanished": 0, "skipped": 2, "held_retry": 0, "pending_reboot": 0, "failed": 1 } }
            """;
        var r = EngineDocs.ReadExec(json, ExitCodes.Partial);
        Assert.Equal(ExitCodes.Partial, r.ExitCode);
        Assert.Equal(("Skipped", "ChangedSinceScan", false), (r.Items[0].Outcome, r.Items[0].Detail, r.Items[0].Complete));
        Assert.Equal(("Failed", "AccessDenied: locked"), (r.Items[1].Outcome, r.Items[1].Detail));
        Assert.True(r.Items[2].Complete);
        Assert.Equal(2, r.Skipped);
        Assert.Equal(1, r.Failed);
    }

    [Fact]
    public void UndoReport()
    {
        var u = EngineDocs.ReadUndo(Sample("rig-undo.json"), 0);
        Assert.Equal("Undone", u.State);
        Assert.Equal(2, u.Restored);
        Assert.Equal(0, u.Conflicts + u.Failed + u.AlreadyRestored + u.NothingToUndo);
    }

    [Fact]
    public void RecoveryListsAndResults()
    {
        Assert.Empty(EngineDocs.ReadRecover(Sample("rig-recover.json")));
        const string pending = """
            { "schema": "purge.cli.recover/1", "sessions": [
              { "session": "20261115T101502Z-9f3a6c1d2b7e4a50", "kind": "Run", "app": "notepad++", "detail": "" } ] }
            """;
        var p = Assert.Single(EngineDocs.ReadRecover(pending));
        Assert.Equal(("20261115T101502Z-9f3a6c1d2b7e4a50", "Run", "notepad++"), (p.SessionId, p.Kind, p.App));

        const string done = """
            { "schema": "purge.cli.recovered/1", "mode": "rollback", "sessions": [
              { "session": "s1", "state": "Undone", "settled": [ {} ], "undone": [ {}, {} ] },
              { "session": "s2", "error": "damaged", "exit": 9 } ] }
            """;
        var r = EngineDocs.ReadRecovered(done, 9);
        Assert.True(r.Rollback);
        Assert.Equal(["s1: Undone, 1 settled, 2 undone", "s2: damaged"], r.Lines);
    }

    [Fact]
    public void SessionIndexAsVaultBatches()
    {
        string? Report(string id) => id == "20261115T223530Z-cada70265f85311e" ? Sample("rig-report.json") : null;
        var status = EngineDocs.ReadIndex(Sample("rig-index.json"), Report, _ => 100L << 30);
        var b = Assert.Single(status.Batches);
        Assert.Equal("20261115T223530Z-cada70265f85311e", b.SessionId);
        Assert.Equal("Purge rig targets", b.ProgramName);
        Assert.Equal((2, 0, 11L), (b.FileItems, b.RegistryItems, b.Bytes));
        Assert.Equal(BatchState.Undoable, b.State);
        Assert.Equal(@"C:\", b.Volume);
        Assert.Equal(2026, b.Created.UtcDateTime.Year);
        var v = Assert.Single(status.Volumes);
        Assert.Equal((@"C:\", 11L, 5L << 30), (v.Volume, v.UsedBytes, v.CapBytes));

        // An installer's empty index, and an undone session without a readable report.
        Assert.Empty(EngineDocs.ReadIndex("{}", _ => null, _ => null).Batches);
        var undone = Sample("rig-index.json").Replace("\"Committed\"", "\"Undone\"");
        Assert.Equal(BatchState.Restored, EngineDocs.ReadIndex(undone, _ => null, _ => null).Batches[0].State);
    }

    [Fact]
    public void VersionLines()
    {
        Assert.Equal(("0.1.0", false, false), EngineDocs.ReadVersion("purge-engine 0.1.0\n"));
        Assert.Equal(("0.1.0", false, true), EngineDocs.ReadVersion("purge-engine 0.1.0\nrig-exec build: executor verbs run headless\n"));
        Assert.Equal(("0.1.0", true, true), EngineDocs.ReadVersion(
            "purge-engine 0.1.0\r\nrig-exec build: x\r\nSANDBOX DEV BUILD: destructive verbs run only inside Sandboxie\r\n"));
    }

    [Fact]
    public void ExitCodesReadAsSentences()
    {
        const string stderr = "[  0.001s] exec\npurge-engine: error: exec: this is a SANDBOX DEV BUILD and the process is not running inside Sandboxie\n";
        var detail = ExitCodes.ErrorLines(stderr);
        Assert.StartsWith("exec: this is a SANDBOX DEV BUILD", detail);
        var text = ExitCodes.Describe(ExitCodes.NotInSandbox, detail);
        Assert.Contains("only inside Sandboxie", text);
        Assert.Contains("Nothing was done", text);
        Assert.Contains("Resume it or roll it back", ExitCodes.Describe(ExitCodes.NeedsRecovery, ""));
        // The engine's codes: 12 is m2's unrecorded session, 13 the sandbox dev refusal.
        Assert.Equal(12, ExitCodes.Unrecorded);
        Assert.Equal(13, ExitCodes.NotInSandbox);
        Assert.Contains("could not finish recording", ExitCodes.Describe(ExitCodes.Unrecorded, ""));
        Assert.Contains("exit code 14", ExitCodes.Describe(14, ""));
        Assert.Contains("exit code 99", ExitCodes.Describe(99, ""));
        var e = Assert.Throws<EngineException>(() =>
            CliEngineClient.Expect(new CliEngineClient.Run("exec", 8, "", "purge-engine: error: session(s) x were interrupted"), 0, 10));
        Assert.True(e.NeedsRecovery);
        Assert.Contains("were interrupted", e.Message);
        CliEngineClient.Expect(new CliEngineClient.Run("exec", 10, "", ""), 0, 10);
    }

    [Fact]
    public async Task EngineRunsAreTrackedAndDisposeEndsThem()
    {
        // A stand-in engine that sleeps: cmd.exe /c ping -n 30 127.0.0.1 (no engine is run here).
        var cmd = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var client = new CliEngineClient(cmd);
        Assert.True(client.HasJob);
        var run = client.RunAsync("sleep", ["/c", "ping -n 30 127.0.0.1 >nul"], null, CancellationToken.None);
        for (var i = 0; i < 50 && client.RunningCount == 0; i++) await Task.Delay(100);
        Assert.Equal(1, client.RunningCount);
        var started = DateTime.UtcNow;
        await client.DisposeAsync();
        var done = await run.WaitAsync(TimeSpan.FromSeconds(15));
        Assert.NotEqual(0, done.Code);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(12));
        Assert.Equal(0, client.RunningCount);
        await Assert.ThrowsAsync<ObjectDisposedException>(() => client.RunAsync("x", [], null, CancellationToken.None));
    }

    [Fact]
    public async Task CancellingARunKillsIt()
    {
        var client = new CliEngineClient(Path.Combine(Environment.SystemDirectory, "cmd.exe"));
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(500));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            client.RunAsync("sleep", ["/c", "ping -n 30 127.0.0.1 >nul"], null, cts.Token));
        Assert.Equal(0, client.RunningCount);
        await client.DisposeAsync();
    }

    [Fact]
    public void SelectionFileIsAJsonArray()
    {
        using var doc = System.Text.Json.JsonDocument.Parse(CliEngineClient.IdsJson(["a", "b\"c", "é"]));
        Assert.Equal(["a", "b\"c", "é"], doc.RootElement.EnumerateArray().Select(e => e.GetString()));
        Assert.Equal("[]", CliEngineClient.IdsJson([]));
    }
}
