using System.Diagnostics;
using Purge.App.Shell;
using Purge.App.Views;
using Purge.Client.Broker;
using Purge.Client.Pipeline;
using Purge.Client.Rpc;
using Xunit;
using RpcBand = Purge.Client.Rpc.Band;
using RpcCategory = Purge.Client.Rpc.Category;

namespace Purge.Client.Tests;

/// <summary>
/// The Leftovers page's view model: paging, the tick rules, re-ticking by CandidateId after a re-scan,
/// plan_refused rendering, the waiting state (consent.shown), the three result outcomes and a broker
/// that dies mid-execute. The real broker and UAC are VM tests.
/// </summary>
public sealed class LeftoversPageTests
{
    [Fact]
    public async Task PagingReadsEveryPageInOrder()
    {
        var broker = new ScriptedBroker();
        for (var i = 0; i < 2_000; i++) broker.Rows.Add(Row(i, pre: true));
        var vm = new LeftoversViewModel(broker);
        var watch = Stopwatch.StartNew();
        await vm.ScanAsync("s-1", null, forced: false);
        watch.Stop();
        Console.WriteLine($"S3 view model: {vm.Items.Count} items in {watch.Elapsed.TotalMilliseconds:F1} ms");

        Assert.Equal(LeftoversPhase.Review, vm.Phase);
        Assert.Equal(2_000, vm.Items.Count);
        Assert.Equal(4, broker.PageCalls.Count);
        Assert.All(broker.PageCalls, call => Assert.Equal(LeftoversViewModel.CandidatePageSize, call.Limit));
        Assert.Equal(new uint[] { 0, 500, 1000, 1500 }, broker.PageCalls.Select(c => c.Offset).ToArray());
        Assert.Equal(LeftoversPhase.Review, vm.Phase);
        Assert.True(vm.CanMove);
    }

    [Fact]
    public void TheBenchFixtureHasTheAskedCountUniqueIdsAndEveryGroupOfTheSample()
    {
        var vm = new LeftoversViewModel(new ScriptedBroker());
        vm.LoadSample(count: 2_000);

        Assert.Equal(LeftoversPhase.Review, vm.Phase);
        Assert.Equal(2_000, vm.Items.Count);
        Assert.Equal(2_000, vm.Items.Select(i => i.CandidateId).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(2_000, vm.Items.Select(i => i.DisplayName).Distinct(StringComparer.Ordinal).Count());

        var sample = new LeftoversViewModel(new ScriptedBroker());
        sample.LoadSample();
        Assert.Equal(sample.Groups.Select(g => g.Name), vm.Groups.Select(g => g.Name));
        // The sample's one Protected item in ten stays one in ten.
        Assert.Equal(200, vm.Items.Count(i => i.IsProtected));
        // count 0 is the 10-item sample, as before.
        Assert.Equal(10, sample.Items.Count);
    }

    [Fact]
    public async Task AForcedScanPreselectsNothing()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.Rows.Add(Row(2, pre: true));
        var vm = new LeftoversViewModel(broker);

        await vm.ScanAsync("s-1", null, forced: true);

        Assert.All(vm.Items, item => Assert.False(item.Checked));
        Assert.False(vm.CanMove);
        Assert.Equal(ScanMode.Forced, vm.Scan!.Mode);
    }

    [Fact]
    public async Task GroupBoxTicksSafeOnlyAndEachRowNeedsItsOwnTick()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, RpcBand.Safe, pre: true));
        broker.Rows.Add(Row(2, RpcBand.Likely));
        broker.Rows.Add(Row(3, RpcBand.Likely, RpcCategory.UserData));
        broker.Rows.Add(Row(4, RpcBand.Blocked));
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);
        var safe = vm.Items.Single(i => i.CandidateId == Id(1));
        var likely = vm.Items.Single(i => i.CandidateId == Id(2));
        var userData = vm.Items.Single(i => i.CandidateId == Id(3));
        var blocked = vm.Items.Single(i => i.CandidateId == Id(4));

        Assert.True(safe.Checked);
        Assert.False(likely.Checked);
        Assert.False(userData.Checked);
        Assert.False(blocked.Checked);

        // A Likely or user-data row needs its own tick; a Protected row can never be ticked.
        vm.SetChecked(likely, true);
        vm.SetChecked(userData, true);
        vm.SetChecked(blocked, true);
        Assert.True(likely.Checked);
        Assert.True(userData.Checked);
        Assert.False(blocked.Checked);
        Assert.False(blocked.Selectable);

        // Start over with only the Safe tick; the group box fills the Safe items and nothing else.
        vm.SetChecked(likely, false);
        vm.SetChecked(userData, false);
        safe.Checked = false;
        var group = vm.Groups.Single(g => g.Name == "Files & folders");
        vm.ToggleGroup(group);
        Assert.True(safe.Checked);
        Assert.False(likely.Checked);
        Assert.False(userData.Checked);
        Assert.False(blocked.Checked);

        // With every selectable row ticked, a second group click unticks the group.
        vm.SetChecked(likely, true);
        vm.SetChecked(userData, true);
        vm.ToggleGroup(group);
        Assert.False(safe.Checked);
        Assert.False(likely.Checked);
        Assert.False(userData.Checked);
    }

    [Fact]
    public async Task RescanReappliesTicksByCandidateId()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1));
        broker.Rows.Add(Row(2, pre: true));
        broker.Rows.Add(Row(3));
        broker.Rows.Add(Row(5));
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);
        Assert.True(Item(vm, 2).Checked);

        vm.SetChecked(Item(vm, 2), false);
        vm.SetChecked(Item(vm, 3), true);
        vm.SetChecked(Item(vm, 5), true);

        broker.Rows.Clear();
        broker.Rows.Add(Row(1, pre: true));
        broker.Rows.Add(Row(3));
        broker.Rows.Add(Row(4, pre: true));
        await vm.RescanAsync();

        Assert.True(Item(vm, 3).Checked);
        Assert.False(Item(vm, 1).Checked, "a new scan's preselection does not override the old ticks");
        Assert.False(Item(vm, 4).Checked);
        Assert.Contains("1 new item", vm.RescanMessage);
        Assert.Contains("2 gone (1 of them ticked)", vm.RescanMessage);
        Assert.Equal(LeftoversPhase.Review, vm.Phase);
    }

    [Fact]
    public async Task PlanRefusedRendersTheItemsUnticked()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.Rows.Add(Row(2, pre: true));
        broker.CreatePlanHook = _ => throw new BrokerRpcException(6, "plan_refused", "bind refused the plan",
            new ErrorData
            {
                Kind = "plan_refused",
                Refusals = [new Refusal { CandidateId = Id(2), Reason = "it cannot be backed up" }],
            });
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);

        await vm.MoveAsync();

        Assert.Equal(LeftoversPhase.Review, vm.Phase);
        Assert.Null(vm.Plan);
        Assert.True(Item(vm, 2).Refused);
        Assert.False(Item(vm, 2).Checked);
        Assert.Contains("cannot be backed up", Item(vm, 2).RefusalReason);
        Assert.True(Item(vm, 1).Checked);
        Assert.Single(vm.RefusalLines);
        Assert.Contains("cannot be quarantined", vm.Error);
        Assert.True(vm.CanMove, "the item that was not refused keeps its tick");
        Assert.Equal(0, broker.ExecuteCalls);
    }

    [Fact]
    public async Task WaitingStateShowsTheCodeWhenTheBrokerDialogIsUp()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        broker.CreatePlanHook = _ => Task.FromResult(Plan("A1B2-C3D4"));
        broker.ExecuteHook = async _ =>
        {
            broker.RaiseConsentShown("A1B2-C3D4");
            await gate.Task;
            return Complete(1, 0, session: "sess-1");
        };
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);

        var move = vm.MoveAsync();

        await WaitUntil(() => vm.Phase == LeftoversPhase.Waiting && vm.PromptUp, "the waiting state");
        Assert.Equal("A1B2-C3D4", vm.Code);
        Assert.Contains("Nothing has been moved", vm.WaitingDetail);
        Assert.Contains("Confirm in the Purge security prompt", vm.WaitingTitle);

        gate.SetResult();
        await move;
        Assert.Equal(LeftoversPhase.Result, vm.Phase);
        Assert.Equal(1, broker.ExecuteCalls);
    }

    [Fact]
    public async Task AttentionRowsComeFromPlanCreateIncludingAbsorbedIds()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        var absorbed = "c-00000000abad1dea";
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        broker.CreatePlanHook = _ => Task.FromResult(Plan("A1B2-C3D4",
            new AttentionItem
            {
                CandidateId = absorbed,
                DisplayName = @"C:\Users\tester\AppData\Local\Mozilla\cache",
                Band = RpcBand.Likely,
                Kind = ItemKind.Folder,
                Reasons = [AttentionReason.Inside, AttentionReason.UserData],
            }));
        broker.ExecuteHook = async _ =>
        {
            broker.RaiseConsentShown("A1B2-C3D4");
            await gate.Task;
            return Complete(1, 0, session: "sess-1");
        };
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);
        var move = vm.MoveAsync();
        await WaitUntil(() => vm.Attention.Count == 1 && vm.PromptUp, "the attention list");

        var attention = Assert.Single(vm.Attention);
        Assert.Equal(absorbed, attention.CandidateId);
        Assert.Contains("inside another item", attention.ReasonsText);
        Assert.Contains("holds your data", attention.ReasonsText);
        Assert.DoesNotContain(vm.Items, item => item.CandidateId == absorbed);

        gate.SetResult();
        await move;
    }

    [Fact]
    public async Task CompleteResultNamesMovedAndAlreadyGone()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.Rows.Add(Row(2, pre: true));
        broker.Rows.Add(Row(3, pre: true));
        broker.CreatePlanHook = _ => Task.FromResult(Plan());
        broker.ExecuteHook = _ => Task.FromResult(new ExecResult
        {
            Outcome = Outcome.Complete,
            Session = "sess-1",
            Counts = new OutcomeCounts { Done = 2, Vanished = 1 },
            RestorePoint = new RestorePointOutcome { Kind = "Created", Sequence = 42 },
        });
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);

        await vm.MoveAsync();

        Assert.Equal(LeftoversPhase.Result, vm.Phase);
        Assert.Contains("Moved 3 items", vm.ResultTitle);
        Assert.Contains("2 moved", vm.ResultDetail);
        Assert.Contains("1 already gone", vm.ResultDetail);
        Assert.Contains("42", vm.RestorePointText);
        Assert.True(vm.CanUndo);
        Assert.False(vm.CanRetryHeld);
    }

    [Fact]
    public async Task PartialResultShowsHeldLockersAndFailures()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.Rows.Add(Row(2, pre: true));
        broker.Rows.Add(Row(3, pre: true));
        broker.CreatePlanHook = _ => Task.FromResult(Plan());
        broker.ExecuteHook = _ => Task.FromResult(new ExecResult
        {
            Outcome = Outcome.Partial,
            Session = "sess-1",
            Counts = new OutcomeCounts { Done = 1, HeldRetry = 1, Failed = 1 },
            Held =
            [
                new HeldItem
                {
                    DisplayName = @"C:\Program Files\Mozilla\firefox.exe",
                    Op = 2,
                    Lockers = [new Locker { Name = "firefox.exe", Pid = 4242 }],
                },
            ],
            RestorePoint = new RestorePointOutcome { Kind = "NotRequested" },
        });
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);

        await vm.MoveAsync();

        Assert.Equal(LeftoversPhase.Result, vm.Phase);
        Assert.Contains("Moved 1 of 3 items", vm.ResultTitle);
        var held = Assert.Single(vm.HeldLines);
        Assert.Contains("firefox.exe", held);
        Assert.Contains("4242", held);
        Assert.Contains("1 could not be moved", Assert.Single(vm.FailedLines));
        Assert.True(vm.CanRetryHeld);
        Assert.Null(vm.RestorePointText);
    }

    [Fact]
    public async Task AResultThatWasNotClosedSaysHistoryOffersRecovery()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.CreatePlanHook = _ => Task.FromResult(Plan());
        broker.ExecuteHook = _ => Task.FromResult(new ExecResult
        {
            Outcome = Outcome.NotClosed,
            Session = "sess-1",
            Counts = new OutcomeCounts { Done = 1 },
            RestorePoint = new RestorePointOutcome { Kind = "NotRequested" },
        });
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);

        await vm.MoveAsync();

        Assert.Equal("The session was not recorded completely", vm.ResultTitle);
        Assert.Contains("History & undo offers recovery", vm.ResultDetail);
    }

    [Fact]
    public async Task BrokerDeathMidExecuteNeverClaimsAResult()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.CreatePlanHook = _ => Task.FromResult(Plan());
        broker.ExecuteHook = _ => throw new BrokerLinkException("The administrator part ended.");
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);

        await vm.MoveAsync();

        Assert.Equal(LeftoversPhase.Interrupted, vm.Phase);
        Assert.Null(vm.Result);
        Assert.Null(vm.ResultTitle);
        Assert.Contains("cannot tell", vm.Error);
        Assert.Contains("History & undo", vm.Error);
        Assert.False(vm.CanUndo);
    }

    [Fact]
    public async Task ConsentDeclinedDoesNothing()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.CreatePlanHook = _ => Task.FromResult(Plan("A1B2-C3D4"));
        broker.ExecuteHook = _ => throw new BrokerRpcException(0, "consent_declined", "cancelled");
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);

        await vm.MoveAsync();

        Assert.Equal(LeftoversPhase.Review, vm.Phase);
        Assert.Null(vm.Result);
        Assert.Contains("Nothing was moved", vm.Info);
        Assert.True(Item(vm, 1).Checked);
    }

    [Fact]
    public async Task S2CompletesHandsTheScanToS3AndThePlanRunsToTheResult()
    {
        // S2: a broker-route uninstall runs, the broker scans, and the controller completes.
        var s2 = new S2Broker();
        var controller = new UninstallController(
            _ => Task.FromResult(new UninstallLaunch(UninstallLaunchState.Started, s2, "")),
            new NoMedium());
        var asked = new TaskCompletionSource<UninstallConfirmation>(TaskCreationOptions.RunContinuationsAsynchronously);
        controller.ConfirmationRequested += c => asked.TrySetResult(c);
        var begin = controller.BeginAsync(new UninstallTarget("prog-1", "Mozilla Firefox"));
        _ = await asked.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: false, RestorePoint.Always));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));
        var outcome = controller.CompletedOutcome!;
        Assert.Equal("scan-from-s2", outcome.ScanId);
        Assert.Equal(1, s2.ScanCalls);

        // S3: the request S2 builds, then candidate paging for the scan it was handed (no second scan).
        var s3 = new ScriptedBroker();
        s3.Rows.Add(Row(1, pre: true));
        var request = new LeftoversRequest(outcome.Target.ProgramId, outcome.Target.ProgramName, outcome.SessionId,
            outcome.ScanId, outcome.Mode, outcome.RestorePoint, outcome.Quiet, Broker: null);
        var vm = new LeftoversViewModel(s3);
        await vm.ShowRequestAsync(request);

        Assert.Equal(0, s3.ScanCalls);
        Assert.Equal("scan-from-s2", vm.Scan!.ScanId);
        Assert.Equal("Mozilla Firefox", vm.ProgramName);
        Assert.True(Item(vm, 1).Checked);

        // plan.create, then plan.execute with the confirm dialog's restore-point choice, then the result.
        await vm.MoveAsync(request.RestorePoint);

        Assert.Equal(1, s3.CreatePlanCalls);
        Assert.Equal(1, s3.ExecuteCalls);
        Assert.Equal(RestorePoint.Always, s3.LastRestorePoint);
        Assert.Equal(LeftoversPhase.Result, vm.Phase);
        Assert.Contains("Moved 1 item", vm.ResultTitle);
        Assert.True(vm.CanUndo);
    }

    private static LeftoverItemModel Item(LeftoversViewModel vm, int n) =>
        vm.Items.Single(i => i.CandidateId == Id(n));

    private static string Id(int n) => $"c-{n:x16}";

    private static CandidateRow Row(int n, RpcBand band = RpcBand.Safe,
        RpcCategory category = RpcCategory.AppFiles, ItemKind kind = ItemKind.File, bool pre = false) => new()
    {
        CandidateId = Id(n),
        DisplayName = $@"C:\Users\tester\AppData\Local\Leftover\{n}",
        Band = band,
        Category = category,
        Kind = kind,
        Preselected = pre,
        SizeBytes = 1024,
        Warnings = [],
    };

    private static PlanCreated Plan(string code = "A1B2-C3D4", params AttentionItem[] attention) => new()
    {
        PlanId = "p-0123456789abcdef",
        PlanHash = "hash",
        Code = code,
        Counts = new PlanCounts { Items = 1, Ticked = 1, Preselected = 1 },
        Bytes = 1024,
        Attention = [.. attention],
        Warnings = [],
    };

    private static ExecResult Complete(uint done, uint vanished, string session) => new()
    {
        Outcome = Outcome.Complete,
        Session = session,
        Counts = new OutcomeCounts { Done = done, Vanished = vanished },
        RestorePoint = new RestorePointOutcome { Kind = "NotRequested" },
    };

    private static async Task WaitUntil(Func<bool> condition, string what)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (!condition())
        {
            if (DateTime.UtcNow > deadline) throw new TimeoutException("timed out waiting for " + what);
            await Task.Delay(10);
        }
    }

    /// <summary>A broker played by the test: rows, plans and outcomes, one scripted answer per method.</summary>
    private sealed class ScriptedBroker : ILeftoversBroker
    {
        public event Action<ConsentShown>? ConsentShown;

        public event Action<BaselineChanged>? BaselineChanged
        {
            add { }
            remove { }
        }

        public bool IsLive { get; set; } = true;
        public List<CandidateRow> Rows { get; } = [];
        public List<(uint Offset, int Limit)> PageCalls { get; } = [];
        public int ScanCalls { get; private set; }
        public int ExecuteCalls { get; private set; }
        public ConsentShown? Shown { get; private set; }

        public Func<IReadOnlyList<string>, Task<PlanCreated>> CreatePlanHook { get; set; } = _ => Task.FromResult(Plan());
        public Func<string, Task<ExecResult>> ExecuteHook { get; set; } = _ => Task.FromResult(Complete(1, 0, "sess-1"));
        public int CreatePlanCalls { get; private set; }
        public RestorePoint LastRestorePoint { get; private set; }

        public void RaiseConsentShown(string code)
        {
            Shown = new ConsentShown { Code = code, Request = 1 };
            ConsentShown?.Invoke(Shown);
        }

        public Task<ScanResult> ScanSessionAsync(string sessionId, bool forced, IProgress<Progress>? progress, CancellationToken ct)
        {
            ScanCalls++;
            return Task.FromResult(new ScanResult
            {
                ScanId = "scan-1",
                Mode = forced ? ScanMode.Forced : ScanMode.Post,
                BaselineTrust = BaselineTrust.Exact,
                Counts = new BandCounts(),
                Warnings = [],
            });
        }

        public Task<ScanResult> ScanStoredAsync(string programId, IProgress<Progress>? progress, CancellationToken ct) =>
            ScanSessionAsync(programId, true, progress, ct);

        public Task<CandidatesPage> CandidatesAsync(string scanId, uint offset, int limit, CancellationToken ct)
        {
            PageCalls.Add((offset, limit));
            var items = Rows.Skip((int)offset).Take(limit).ToList();
            return Task.FromResult(new CandidatesPage { Offset = offset, Total = (uint)Rows.Count, Items = items });
        }

        public Task<Explanation> ExplainAsync(string scanId, string candidateId, CancellationToken ct) =>
            Task.FromResult(new Explanation
            {
                CandidateId = candidateId,
                Evidence = ["Inside Mozilla's install folder", "Not on clean Windows 11"],
                Blockers = [],
            });

        public Task<PlanCreated> CreatePlanAsync(string scanId, IReadOnlyList<string> selected, CancellationToken ct)
        {
            CreatePlanCalls++;
            return CreatePlanHook(selected);
        }

        public Task<ExecResult> ExecuteAsync(string planId, RestorePoint restorePoint, IProgress<Progress>? progress, CancellationToken ct)
        {
            ExecuteCalls++;
            LastRestorePoint = restorePoint;
            return ExecuteHook(planId);
        }

        public Task<UndoResult> UndoAsync(string session, IProgress<Progress>? progress, CancellationToken ct) =>
            Task.FromResult(new UndoResult { Outcome = Outcome.Complete, Conflicts = [] });

        public Task<OutcomeResult> RetryHeldAsync(string session, CancellationToken ct) =>
            Task.FromResult(new OutcomeResult { Outcome = Outcome.Complete });
    }

    /// <summary>The S2 side of the end-to-end test: a broker-route prepare, run and scan.</summary>
    private sealed class S2Broker : IUninstallBroker
    {
        public int ScanCalls { get; private set; }

        public event Action<ConsentShown>? ConsentShown
        {
            add { }
            remove { }
        }

        public Task<PrepareResult> PrepareAsync(IReadOnlyList<string> programIds, Action<Progress>? progress, CancellationToken ct) =>
            Task.FromResult(new PrepareResult
            {
                Programs =
                [
                    new Prepared
                    {
                        ProgramId = programIds[0],
                        SessionId = "us-1",
                        Route = Route.Broker,
                        Command = @"""C:\Program Files\App\unins000.exe""",
                        FingerprintSummary = new FingerprintSummary(),
                        CoProducts = [],
                        Running = [],
                        Warnings = [],
                    },
                ],
            });

        public Task<RunResult> RunAsync(string sessionId, bool quiet, RestorePoint restorePoint, Action<Progress>? progress,
            CancellationToken ct) =>
            Task.FromResult(new RunResult
            {
                ExitCode = 0,
                Outcome = RunOutcome.Success,
                VerifyGone = new VerifyGone { ArpGone = true, MainExesGone = true, MsiUnknownAllCtx = true, Passed = true },
            });

        public Task<ObservedResult> ObservedAsync(string sessionId, RunOutcome? outcome, CancellationToken ct) =>
            Task.FromResult(new ObservedResult
            {
                VerifyGone = new VerifyGone { ArpGone = true, MainExesGone = true, MsiUnknownAllCtx = true, Passed = true },
            });

        public Task<ScanResult> ScanAsync(string sessionId, bool forced, Action<Progress>? progress, CancellationToken ct)
        {
            ScanCalls++;
            return Task.FromResult(new ScanResult
            {
                ScanId = "scan-from-s2",
                Mode = forced ? ScanMode.Forced : ScanMode.Post,
                BaselineTrust = BaselineTrust.Exact,
                Counts = new BandCounts(),
                Warnings = [],
            });
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class NoMedium : IMediumUninstall
    {
        public Task<RouteInfo> RouteAsync(string programId, CancellationToken ct) =>
            throw new InvalidOperationException("a broker-route program never asks the medium engine");

        public Task<RunUserResult> RunUserAsync(string programId, bool quiet, Action<Progress>? progress, CancellationToken ct) =>
            throw new InvalidOperationException("a broker-route program never runs in the medium engine");
    }
}
