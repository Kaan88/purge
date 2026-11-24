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
    public async Task RegistryRowsGetAReadableLabelAndKeepTheRawPath()
    {
        const string sid = "S-1-5-21-1111111111-2222222222-3333333333-1001";
        const string raw = @"HKU\" + sid + @"\Software\Mozilla\Firefox";
        var broker = new ScriptedBroker();
        var row = Row(1, RpcBand.Safe, RpcCategory.Registration, ItemKind.RegistryKey, pre: true);
        row.DisplayName = raw;
        broker.Rows.Add(row);
        broker.Rows.Add(Row(2, pre: true));
        var vm = new LeftoversViewModel(broker, currentUserSid: sid);
        await vm.ScanAsync("s-1", null, forced: false);

        var key = vm.Items.Single(i => i.CandidateId == Id(1));
        Assert.Equal(raw, key.DisplayName);
        Assert.Equal("Settings of Mozilla Firefox", key.Title);
        Assert.Equal("Your account › Software", key.Location);

        // A file row has no label: the raw path stays its main line.
        var file = vm.Items.Single(i => i.CandidateId == Id(2));
        Assert.Null(file.Label);
        Assert.Equal(file.DisplayName, file.Title);
        Assert.Equal("", file.Location);

        // Without the user's SID the same key belongs to "another account".
        var other = new LeftoversViewModel(broker);
        await other.ScanAsync("s-1", null, forced: false);
        Assert.Equal("Another account › Software", other.Items.Single(i => i.CandidateId == Id(1)).Location);
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
        // The shell must not hand this page another broker link now (LeftoversNavigator.TryShow).
        Assert.True(vm.IsChanging);

        gate.SetResult();
        await move;
        Assert.Equal(LeftoversPhase.Result, vm.Phase);
        Assert.False(vm.IsChanging);
        Assert.Equal(1, broker.ExecuteCalls);
    }

    // ------------------------------------------------------------------------------------------------------------
    // "Delete instead of keeping in quarantine" (DECISIONS 2026-11-24).
    // ------------------------------------------------------------------------------------------------------------

    private static ExecResult Deleted(DeleteAfterOutcome outcome, uint purged, uint kept)
    {
        var result = Complete(1, 0, "sess-1");
        result.DeleteAfter = new DeleteAfter { Outcome = outcome, Purged = purged, Kept = kept };
        return result;
    }

    [Fact]
    public async Task QuarantineIsTheDefaultAndTheMoveAsksForNoDelete()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);

        Assert.False(vm.DeleteAfter);
        Assert.Equal("Move 1 item to quarantine…", vm.MoveText);
        Assert.Equal("Delete instead of keeping in quarantine", LeftoversViewModel.DeleteAfterText);
        await vm.MoveAsync();

        Assert.Equal(1, broker.ExecuteCalls);
        Assert.Equal(0, broker.DeleteCalls);
        Assert.Null(vm.DeleteAfterResult);
        Assert.Equal("Moved 1 item to quarantine", vm.ResultTitle);
    }

    [Fact]
    public async Task TheTickAsksTheBrokerForTheDeleteStepAndTheResultSaysWhatItDid()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.DeleteHook = (_, _) => Task.FromResult(Deleted(DeleteAfterOutcome.Deleted, 1, 0));
        var foreground = 0;
        var vm = new LeftoversViewModel(broker, () => foreground++);
        await vm.ScanAsync("s-1", null, forced: false);

        var changed = new List<string?>();
        vm.PropertyChanged += (_, e) => changed.Add(e.PropertyName);
        vm.DeleteAfter = true;
        Assert.Equal("Move 1 item, then delete it…", vm.MoveText);
        // The tick changes the button's words and nothing else (no list rebuild).
        Assert.Equal([nameof(vm.DeleteAfter), nameof(vm.MoveText)], changed);

        await vm.MoveAsync(RestorePoint.Off);

        // One request, the one with the delete step; the plain execute is not also sent.
        Assert.Equal(1, broker.DeleteCalls);
        Assert.Equal(0, broker.ExecuteCalls);
        Assert.Equal(RestorePoint.Off, broker.LastRestorePoint);
        Assert.Equal(LeftoversPhase.Result, vm.Phase);
        Assert.Equal("Moved 1 item to quarantine", vm.ResultTitle);
        Assert.StartsWith("Then deleted for good, as you asked: 1 quarantined item. That cannot be undone.", vm.DeleteAfterResult);
        Assert.Contains("Registry and other changes of this cleanup can still be undone", vm.DeleteAfterResult);
        // Off again for the next move.
        Assert.False(vm.DeleteAfter);
        Assert.True(foreground >= 1);
    }

    [Fact]
    public async Task ADeclinedOrFailedDeleteStepLeavesTheItemsInQuarantineAndSaysSo()
    {
        foreach (var (outcome, purged, kept, starts) in new[]
                 {
                     (DeleteAfterOutcome.Declined, 0u, 2u, "Nothing was deleted: the delete prompt was cancelled. What was moved is in quarantine and can be put back for 30 days"),
                     (DeleteAfterOutcome.Failed, 0u, 2u, "The delete did not go through. What was moved is safe in quarantine and can be put back for 30 days"),
                     (DeleteAfterOutcome.Nothing, 0u, 0u, "Nothing was deleted: this cleanup left nothing in quarantine that can be deleted now."),
                     (DeleteAfterOutcome.Partial, 1u, 1u, "Then deleted for good: 1. Still in quarantine: 1 (declined, or not deletable now); it can be put back for 30 days"),
                 })
        {
            var broker = new ScriptedBroker();
            broker.Rows.Add(Row(1, pre: true));
            broker.DeleteHook = (_, _) => Task.FromResult(Deleted(outcome, purged, kept));
            var vm = new LeftoversViewModel(broker) { };
            await vm.ScanAsync("s-1", null, forced: false);
            vm.DeleteAfter = true;

            await vm.MoveAsync();

            // The move's own result is unchanged; the delete line never claims a delete that did not happen.
            Assert.Equal(LeftoversPhase.Result, vm.Phase);
            Assert.Equal("Moved 1 item to quarantine", vm.ResultTitle);
            Assert.StartsWith(starts, vm.DeleteAfterResult);
            Assert.True(vm.CanUndo);
        }

        // An answer without the step at all (a broker that does not know the request) claims nothing either.
        Assert.StartsWith("The delete step did not run. What was moved is in quarantine",
            LeftoversViewModel.DescribeDeleteAfter(null));
        Assert.DoesNotContain("deleted for good", LeftoversViewModel.DescribeDeleteAfter(null));
    }

    /// <summary>
    /// Review M1: after a delete step that deleted something, the result page never offers "Put back all". Nothing
    /// left to undo: no button. Registry changes left: "Undo registry changes…". Items still in quarantine: "Put
    /// back what is still in quarantine…". Each opens History & undo; no <c>undo.run</c> goes out from this page.
    /// </summary>
    [Fact]
    public async Task AfterADeleteStepTheUndoButtonNeverPromisesWhatWasDeleted()
    {
        async Task<(LeftoversViewModel, ScriptedBroker)> Moved(uint done, DeleteAfter? step)
        {
            var broker = new ScriptedBroker();
            broker.Rows.Add(Row(1, pre: true));
            var result = Complete(done, 0, "sess-1");
            result.DeleteAfter = step;
            broker.DeleteHook = (_, _) => Task.FromResult(result);
            var vm = new LeftoversViewModel(broker);
            await vm.ScanAsync("s-1", null, forced: false);
            vm.DeleteAfter = true;
            await vm.MoveAsync();
            return (vm, broker);
        }

        // Two files moved, both deleted, nothing else changed: nothing to undo, no button.
        var (all, _) = await Moved(2, new DeleteAfter { Outcome = DeleteAfterOutcome.Deleted, Purged = 2 });
        Assert.False(all.CanUndo);

        // Two files deleted and a registry change besides: the registry change can still be undone, from History.
        var (registry, registryBroker) = await Moved(3, new DeleteAfter { Outcome = DeleteAfterOutcome.Deleted, Purged = 2 });
        Assert.True(registry.CanUndo);
        Assert.Equal("Undo registry changes…", registry.UndoText);
        Assert.True(registry.UndoOpensHistory);
        await registry.UndoAllAsync();
        Assert.Equal(0, registryBroker.UndoCalls);
        Assert.Equal(LeftoversPhase.Result, registry.Phase);
        Assert.Null(registry.Error);
        Assert.Equal("Open History & undo to put back what this cleanup still holds.", registry.Info);

        // One deleted, one declined: what is still in quarantine can be put back, from History.
        var (partial, partialBroker) = await Moved(2, new DeleteAfter { Outcome = DeleteAfterOutcome.Partial, Purged = 1, Kept = 1 });
        Assert.True(partial.CanUndo);
        Assert.Equal("Put back what is still in quarantine…", partial.UndoText);
        Assert.True(partial.UndoOpensHistory);
        await partial.UndoAllAsync();
        Assert.Equal(0, partialBroker.UndoCalls);

        // Nothing deleted (declined): everything is in quarantine, the button is the usual one.
        var (declined, declinedBroker) = await Moved(2, new DeleteAfter { Outcome = DeleteAfterOutcome.Declined, Kept = 2 });
        Assert.True(declined.CanUndo);
        Assert.Equal("Put back all", declined.UndoText);
        Assert.False(declined.UndoOpensHistory);

        // A broker link that has ended never gets an undo sent into it, and no "ended while putting things back".
        declinedBroker.IsLive = false;
        Assert.True(declined.UndoOpensHistory);
        await declined.UndoAllAsync();
        Assert.Equal(0, declinedBroker.UndoCalls);
        Assert.Equal(LeftoversPhase.Result, declined.Phase);
        Assert.Null(declined.Error);
    }

    /// <summary>A page that moved one item over <paramref name="broker"/> and has a launcher for a new broker.</summary>
    private static async Task<LeftoversViewModel> MovedWithLauncher(ScriptedBroker broker,
        Func<CancellationToken, Task<LeftoversBrokerLaunch>> launch)
    {
        broker.Rows.Add(Row(1, pre: true));
        var vm = new LeftoversViewModel(broker, relaunch: launch);
        await vm.ScanAsync("s-1", null, forced: false);
        await vm.MoveAsync();
        Assert.Equal(LeftoversPhase.Result, vm.Phase);
        return vm;
    }

    /// <summary>
    /// DECISIONS 2026-11-24 (A): a completed move ends the broker, so "Put back all" over the dead link starts a new
    /// broker in place (the admin explanation, UAC), then sends <c>undo.run</c> for the session over the new one, and
    /// the "Put back" result shows on the same page. Nothing goes into the dead link, and History is not opened.
    /// </summary>
    [Fact]
    public async Task PutBackAllOverAnEndedLinkStartsANewBrokerAndUndoesOnThePage()
    {
        var first = new ScriptedBroker();
        var second = new ScriptedBroker();
        var launches = 0;
        var foreground = 0;
        var vm = await MovedWithLauncher(first, _ =>
        {
            launches++;
            return Task.FromResult(new LeftoversBrokerLaunch(second, false, "", AllowForeground: () => foreground++));
        });
        first.IsLive = false;
        Assert.False(vm.UndoOpensHistory);
        Assert.True(vm.CanUndo);

        var titles = new List<string>();
        vm.Changed += () => titles.Add(vm.WaitingTitle);
        await vm.UndoAllAsync();

        Assert.Equal(1, launches);
        Assert.Equal(0, first.UndoCalls);
        Assert.Equal(1, second.UndoCalls);
        Assert.Equal(1, foreground);
        Assert.Equal(LeftoversPhase.Undone, vm.Phase);
        Assert.Equal("Put back", vm.UndoTitle);
        Assert.Null(vm.Error);
        Assert.Contains(LeftoversViewModel.UndoStartingTitle, titles);
        Assert.Contains(LeftoversViewModel.UndoWaitingTitle, titles);
        // The new broker's prompt reports to the page.
        second.RaiseConsentShown("Z9Y8-X7W6");
        Assert.Equal("Z9Y8-X7W6", vm.Code);
    }

    /// <summary>
    /// The broker refuses because it is closing after the move (its drain), or the request could not be written:
    /// nothing was done, so the page starts a new broker and puts back over it, never "cannot tell what was put back".
    /// </summary>
    [Fact]
    public async Task PutBackAllWhileTheBrokerIsClosingStartsANewBroker()
    {
        foreach (Exception refusal in new Exception[]
                 {
                     new BrokerRpcException(-32000, "runtime", "the broker is closing"),
                     new BrokerLinkException("The administrator part is not running.", notSent: true),
                 })
        {
            var first = new ScriptedBroker { UndoHook = _ => Task.FromException<UndoResult>(refusal) };
            var second = new ScriptedBroker();
            var vm = await MovedWithLauncher(first, _ => Task.FromResult(new LeftoversBrokerLaunch(second, false, "")));
            await vm.UndoAllAsync();
            Assert.Equal(1, first.UndoCalls);
            Assert.Equal(1, second.UndoCalls);
            Assert.Equal(LeftoversPhase.Undone, vm.Phase);
            Assert.Null(vm.Error);
        }

        // Without a launcher, the same refusal says that nothing was put back: no "Interrupted".
        var lone = new ScriptedBroker
        {
            UndoHook = _ => Task.FromException<UndoResult>(new BrokerLinkException("gone", notSent: true)),
        };
        lone.Rows.Add(Row(1, pre: true));
        var page = new LeftoversViewModel(lone);
        await page.ScanAsync("s-1", null, forced: false);
        await page.MoveAsync();
        await page.UndoAllAsync();
        Assert.Equal(LeftoversPhase.Result, page.Phase);
        Assert.StartsWith("Nothing was put back", page.Error);
        Assert.DoesNotContain("cannot tell", page.Error);
    }

    /// <summary>
    /// The admin explanation declined ("Not now") or UAC cancelled: nothing is sent, the page stays on its result and
    /// says "Not put back: administrator permission was not given." — never an interrupted restore.
    /// </summary>
    [Fact]
    public async Task PutBackAllWithoutAdminPermissionSaysNothingWasPutBack()
    {
        foreach (var launch in new[]
                 {
                     new LeftoversBrokerLaunch(null, true, "", DeclinedExplanation: true),
                     new LeftoversBrokerLaunch(null, true, "The Windows prompt was cancelled."),
                 })
        {
            var first = new ScriptedBroker();
            var vm = await MovedWithLauncher(first, _ => Task.FromResult(launch));
            first.IsLive = false;
            await vm.UndoAllAsync();
            Assert.Equal(0, first.UndoCalls);
            Assert.Equal(LeftoversPhase.Result, vm.Phase);
            Assert.Equal("Not put back: administrator permission was not given.", vm.Info);
            Assert.Null(vm.Error);
            Assert.True(vm.CanUndo, "the button is offered again");
        }

        // A launch that failed names its reason, still on the result page.
        var failed = new ScriptedBroker();
        var page = await MovedWithLauncher(failed, _ => Task.FromResult(new LeftoversBrokerLaunch(null, false, "broker missing")));
        failed.IsLive = false;
        await page.UndoAllAsync();
        Assert.Equal(LeftoversPhase.Result, page.Phase);
        Assert.Equal("Not put back: the administrator part could not be started. broker missing", page.Error);
    }

    /// <summary>After a delete step that deleted something, "Put back…" still routes to History, launcher or not.</summary>
    [Fact]
    public async Task AfterADeleteStepTheUndoButtonStillRoutesToHistoryWithALauncher()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        var result = Complete(3, 0, "sess-1");
        result.DeleteAfter = new DeleteAfter { Outcome = DeleteAfterOutcome.Deleted, Purged = 2 };
        broker.DeleteHook = (_, _) => Task.FromResult(result);
        var launches = 0;
        var vm = new LeftoversViewModel(broker, relaunch: _ =>
        {
            launches++;
            return Task.FromResult(new LeftoversBrokerLaunch(new ScriptedBroker(), false, ""));
        });
        await vm.ScanAsync("s-1", null, forced: false);
        vm.DeleteAfter = true;
        await vm.MoveAsync();
        foreach (var live in new[] { true, false })
        {
            broker.IsLive = live;
            Assert.True(vm.UndoOpensHistory);
            await vm.UndoAllAsync();
            Assert.Equal(0, broker.UndoCalls);
            Assert.Equal(0, launches);
            Assert.Equal("Open History & undo to put back what this cleanup still holds.", vm.Info);
        }
    }

    [Fact]
    public async Task TheWaitingStateSaysWhenTheSecondPromptIsTheOneToConfirm()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.CreatePlanHook = _ => Task.FromResult(Plan("A1B2-C3D4"));
        var moved = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var answered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        broker.DeleteHook = async (_, progress) =>
        {
            broker.RaiseConsentShown("A1B2-C3D4");
            await moved.Task;
            progress?.Report(new Progress { Phase = LeftoversViewModel.DeleteAfterPhase, Request = 1 });
            await answered.Task;
            return Deleted(DeleteAfterOutcome.Declined, 0, 1);
        };
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);
        vm.DeleteAfter = true;

        var move = vm.MoveAsync();

        await WaitUntil(() => vm.Phase == LeftoversPhase.Waiting && vm.PromptUp, "the move prompt");
        Assert.Equal("A1B2-C3D4", vm.Code);
        Assert.Contains("Confirm in the Purge security prompt", vm.WaitingTitle);
        Assert.Contains("It approves the move only; a second prompt then asks about deleting", vm.WaitingDetail);

        moved.SetResult();
        await WaitUntil(() => vm.WaitingTitle.Contains("second Purge security prompt"), "the delete step");
        Assert.Equal("The items are in quarantine. Nothing has been deleted yet.", vm.WaitingDetail);
        // The first prompt's code is not shown for the second prompt; the broker announces its own.
        Assert.Null(vm.Code);
        Assert.False(vm.PromptUp);
        broker.RaiseConsentShown("E5F6-A7B8");
        await WaitUntil(() => vm.Code == "E5F6-A7B8" && vm.PromptUp, "the second prompt's code");
        Assert.True(vm.IsChanging);

        answered.SetResult();
        await move;
        Assert.Equal(LeftoversPhase.Result, vm.Phase);
        Assert.StartsWith("Nothing was deleted: the delete prompt was cancelled.", vm.DeleteAfterResult);
    }

    [Fact]
    public async Task ACancelledMovePromptWithTheTickMovesAndDeletesNothing()
    {
        var broker = new ScriptedBroker();
        broker.Rows.Add(Row(1, pre: true));
        broker.DeleteHook = (_, _) => throw new BrokerRpcException(0, "consent_declined", "cancelled");
        var vm = new LeftoversViewModel(broker);
        await vm.ScanAsync("s-1", null, forced: false);
        vm.DeleteAfter = true;

        await vm.MoveAsync();

        Assert.Equal(LeftoversPhase.Review, vm.Phase);
        Assert.Equal("Nothing was moved: the prompt was cancelled.", vm.Info);
        Assert.Null(vm.Result);
        Assert.Null(vm.DeleteAfterResult);
        // The choice is the user's and stays as it was for the next try.
        Assert.True(vm.DeleteAfter);
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

        /// <summary><c>plan.execute {delete_after}</c>: how often, and what it answers (the progress is the call's).</summary>
        public int DeleteCalls { get; private set; }

        public Func<string, IProgress<Progress>?, Task<ExecResult>> DeleteHook { get; set; } =
            (_, _) => Task.FromResult(Complete(1, 0, "sess-1"));

        public Task<ExecResult> ExecuteThenDeleteAsync(string planId, RestorePoint restorePoint, IProgress<Progress>? progress, CancellationToken ct)
        {
            DeleteCalls++;
            LastRestorePoint = restorePoint;
            return DeleteHook(planId, progress);
        }

        public int UndoCalls { get; private set; }

        /// <summary>What <c>undo.run</c> answers; null: a complete undo.</summary>
        public Func<string, Task<UndoResult>>? UndoHook { get; set; }

        public Task<UndoResult> UndoAsync(string session, IProgress<Progress>? progress, CancellationToken ct)
        {
            UndoCalls++;
            return UndoHook?.Invoke(session) ?? Task.FromResult(new UndoResult { Outcome = Outcome.Complete, Conflicts = [] });
        }

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
