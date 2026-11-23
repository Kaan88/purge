using System.Text.Json;
using Purge.App.Views;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The Quarantine vault's view model on real calls (design 7a page table): the list, the use and the real cap per
/// volume from <c>history.index</c> (medium engine, no broker), "Put back…" as <c>undo.run</c> and "Review and
/// delete…" as <c>quarantine.expiring</c> then <c>quarantine.purge</c> through the broker. The real broker, its
/// dialogs and UAC are VM tests.
/// </summary>
public sealed class VaultPageTests
{
    private const string GitSession = "20251115T101502Z-9f3a6c1d2b7e4a50";

    [Fact]
    public async Task ListsWhatTheIndexHoldsWithTheRealCapWithoutStartingTheBroker()
    {
        var index = GitIndex();
        var restored = Fixture<HistoryIndex>("stdio.history.index.result.json").Sessions[0];
        restored.Id = "20251116T080000Z-0000000000000001";
        restored.State = SessionState.Undone;
        index.Sessions.Add(restored);
        var launches = 0;
        var vm = new VaultViewModel(_ => Task.FromResult(index), _ => { launches++; return Launch(new ScriptedVaultBroker()); });

        await vm.LoadAsync();

        Assert.Equal(VaultPhase.Ready, vm.Phase);
        Assert.Equal(0, launches);
        var git = Assert.Single(vm.Batches);
        Assert.Equal(GitSession, git.Id);
        Assert.Equal("HKLM|64|Git_is1", git.Name);
        Assert.Equal(@"C:\", git.Volume);
        Assert.Equal(21u, git.Items);
        Assert.Equal(1234567UL, git.Bytes);
        // The fixture's session is a year old: past both retention dates.
        Assert.True(git.Expired);
        Assert.Equal("Expired", git.State);
        Assert.Equal([git], vm.ExpiredBatches);
        var volume = Assert.Single(vm.Volumes);
        Assert.Equal(@"C:\", volume.Root);
        Assert.Equal(10737418240UL, volume.Cap);
        Assert.Equal(1234567UL, volume.Used);
        Assert.StartsWith("Expired or expiring soon: ", volume.Note);
        Assert.Equal(0, vm.Interrupted);
    }

    [Fact]
    public async Task AFreshSessionIsRestorableWithItsDaysLeft()
    {
        var index = GitIndex();
        var s = index.Sessions[0];
        var now = DateTimeOffset.Now;
        s.Started = (ulong)now.AddDays(-2).ToFileTime();
        s.Expires.Quarantine = (ulong)now.AddDays(28).ToFileTime();
        s.Expires.Backups = (ulong)now.AddDays(178).ToFileTime();
        var vm = new VaultViewModel(_ => Task.FromResult(index), _ => Launch(new ScriptedVaultBroker()));

        await vm.LoadAsync();

        var git = Assert.Single(vm.Batches);
        Assert.False(git.Expired);
        Assert.False(git.Expiring);
        Assert.Equal("Restorable", git.State);
        Assert.Equal(28, git.FileDays);
        Assert.Equal(178, git.BackupDays);
        Assert.Equal("Files restorable for 28 more days · registry backups 178 days", git.Detail);
        Assert.Empty(vm.ExpiredBatches);
        Assert.Equal("Nothing expiring this week", Assert.Single(vm.Volumes).Note);
    }

    [Fact]
    public async Task NothingHeldIsTheEmptyStateAndAnInterruptedSessionIsCounted()
    {
        var index = GitIndex();
        index.Sessions[0].State = SessionState.Open;
        var vm = new VaultViewModel(_ => Task.FromResult(index), _ => Launch(new ScriptedVaultBroker()));

        await vm.LoadAsync();

        Assert.Equal(VaultPhase.Empty, vm.Phase);
        Assert.Empty(vm.Batches);
        Assert.Equal(1, vm.Interrupted);
    }

    [Fact]
    public async Task AnIndexThatCannotBeReadShowsTheError()
    {
        var vm = new VaultViewModel(_ => Task.FromException<HistoryIndex>(new InvalidDataException("index.json is busy")),
            _ => Launch(new ScriptedVaultBroker()));

        await vm.LoadAsync();

        Assert.Equal(VaultPhase.Error, vm.Phase);
        Assert.Equal("index.json is busy", vm.Error);
    }

    [Fact]
    public async Task PutBackRunsUndoForTheWholeSessionAndReadsTheListAgain()
    {
        var broker = new ScriptedVaultBroker { Undo = new UndoResult { Outcome = Outcome.Complete } };
        var reads = 0;
        var vm = new VaultViewModel(_ => { reads++; return Task.FromResult(GitIndex()); }, _ => Launch(broker));
        await vm.LoadAsync();

        await vm.RestoreAsync(GitSession);

        Assert.Equal([(GitSession, (IReadOnlyList<uint>?)null)], broker.UndoCalls);
        Assert.Equal(1, broker.Foreground);
        Assert.Equal("HKLM|64|Git_is1 is back", vm.ResultTitle);
        Assert.Null(vm.ActionError);
        Assert.Equal(2, reads);
        Assert.False(vm.Busy);
    }

    [Fact]
    public async Task ADeclinedPromptPutsNothingBackAndAnotherWriterIsBusy()
    {
        var broker = new ScriptedVaultBroker { UndoError = new BrokerRpcException(-32000, "consent_declined", "declined") };
        var reads = 0;
        var vm = new VaultViewModel(_ => { reads++; return Task.FromResult(GitIndex()); }, _ => Launch(broker));
        await vm.LoadAsync();

        await vm.RestoreAsync(GitSession);
        Assert.Equal("Nothing was put back: the prompt was cancelled.", vm.ActionInfo);
        Assert.Null(vm.ResultTitle);
        Assert.Equal(1, reads);

        broker.UndoError = new BrokerRpcException(-32000, "busy", "a mutating request is running");
        await vm.RestoreAsync(GitSession);
        Assert.Equal("Another Purge window is changing the quarantine. Wait for it to finish, then try again.", vm.ActionError);
    }

    [Fact]
    public async Task ReviewAndDeleteAsksTheBrokerWhatExpiredAndPurgesItThroughItsDialog()
    {
        var broker = new ScriptedVaultBroker
        {
            Expiring = Fixture<ExpiringList>("pipe.quarantine.expiring.result.json"),
            Purge = Fixture<PurgeResult>("pipe.quarantine.purge.result.json"),
        };
        var launches = 0;
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()), _ => { launches++; return Launch(broker); });
        await vm.LoadAsync();

        await vm.ReviewExpiredAsync();

        Assert.Equal(1, launches);
        Assert.Equal(1, broker.ExpiringCalls);
        Assert.Equal([["e-0e0e000000000007"]], broker.PurgeCalls);
        Assert.Equal(1, broker.Foreground);
        Assert.Equal("41 items deleted for good", vm.ResultTitle);
        Assert.Null(vm.ActionInfo);
    }

    [Fact]
    public async Task AnotherWriterSaysNothingWasDeleted()
    {
        var broker = new ScriptedVaultBroker
        {
            Expiring = Fixture<ExpiringList>("pipe.quarantine.expiring.result.json"),
            PurgeError = new BrokerRpcException(-32000, "busy", "another writer holds the store"),
        };
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(broker));
        await vm.LoadAsync();

        await vm.ReviewExpiredAsync();

        Assert.Equal("Another Purge window is changing the quarantine; nothing was deleted. Try again when it has finished.",
            vm.ActionError);
        Assert.Null(vm.ResultTitle);
        Assert.False(vm.Busy);
    }

    [Fact]
    public async Task NothingPastRetentionIsANoteNotADialog()
    {
        var broker = new ScriptedVaultBroker();
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(broker));
        await vm.LoadAsync();

        await vm.ReviewExpiredAsync();

        Assert.Equal(1, broker.ExpiringCalls);
        Assert.Empty(broker.PurgeCalls);
        Assert.Equal("Nothing has passed its retention yet; nothing was deleted.", vm.ActionInfo);
    }

    [Fact]
    public async Task ACancelledAdminPromptStartsNothing()
    {
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()), _ => Task.FromResult(new VaultBrokerLaunch(null, true, "")));
        await vm.LoadAsync();

        await vm.ReviewExpiredAsync();

        Assert.True(vm.PromptCancelled);
        Assert.False(vm.PromptDeclined);
        Assert.Null(vm.ActionError);
        Assert.False(vm.Busy);
    }

    [Fact]
    public async Task NotNowAtTheExplanationIsADeclinedPrompt()
    {
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()),
            _ => Task.FromResult(new VaultBrokerLaunch(null, true, "", DeclinedExplanation: true)));
        await vm.LoadAsync();

        await vm.ReviewExpiredAsync();

        Assert.True(vm.PromptCancelled);
        Assert.True(vm.PromptDeclined);
        Assert.Null(vm.ActionError);
    }

    [Fact]
    public async Task ABrokerThatDiesIsStartedAgainOnTheNextClick()
    {
        var first = new ScriptedVaultBroker { ExpiringError = new BrokerLinkException("pipe closed") };
        var second = new ScriptedVaultBroker();
        var brokers = new Queue<ScriptedVaultBroker>([first, second]);
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(brokers.Dequeue()));
        await vm.LoadAsync();

        await vm.ReviewExpiredAsync();
        Assert.NotNull(vm.ActionError);
        Assert.True(first.Disposed);

        await vm.ReviewExpiredAsync();
        Assert.Null(vm.ActionError);
        Assert.Equal(1, second.ExpiringCalls);
    }

    // ------------------------------------------------------------------------------------------------------------
    // "Delete now": a cleanup's quarantined items before their retention ends (DECISIONS 2026-11-23).
    // ------------------------------------------------------------------------------------------------------------

    private const string OtherSession = "20251116T080000Z-0000000000000001";

    /// <summary>
    /// What the broker lists with <c>include_not_due</c>: two quarantined items of the Git cleanup that are not due
    /// (one of them user data), its registry backup (due), and an item of another cleanup.
    /// </summary>
    private static ExpiringList Held()
    {
        var until = (ulong)DateTimeOffset.Now.AddDays(20).ToFileTime();
        ExpiringItem Item(string id, string session, RetentionClass kind, bool due, string file, bool userData = false) => new()
        {
            ExpiryId = id, Session = session, App = "Git", Class = kind, Due = due, Expired = until, Files = [file],
            Bytes = 2048, UserData = userData,
        };
        return new ExpiringList
        {
            Items =
            [
                Item("e-0000000000000003", GitSession, RetentionClass.Backup, true, @"reg\000003.regbackup.json"),
                Item("e-0000000000000001", GitSession, RetentionClass.Quarantine, false, @"C:\Program Files\Git"),
                Item("e-0000000000000002", GitSession, RetentionClass.Quarantine, false, @"C:\Users\u\Documents\Git", userData: true),
                Item("e-0000000000000004", OtherSession, RetentionClass.Quarantine, false, @"C:\Program Files\Other"),
            ],
        };
    }

    [Fact]
    public async Task DeleteNowSendsTheBrokersIdsOfThatCleanupsQuarantinedItemsAndNothingElse()
    {
        var broker = new ScriptedVaultBroker { Expiring = Held(), Purge = new PurgeResult { Outcome = Outcome.Complete, Purged = 2 } };
        var reads = 0;
        var vm = new VaultViewModel(_ => { reads++; return Task.FromResult(GitIndex()); }, _ => Launch(broker));
        await vm.LoadAsync();

        await vm.DeleteNowAsync(GitSession);

        // The listing asked for the items that are not due; the delete names ids, not paths: never the backup, never
        // another cleanup's item.
        Assert.Equal([true], broker.ExpiringFlags);
        Assert.Equal([["e-0000000000000001", "e-0000000000000002"]], broker.PurgeCalls);
        Assert.Equal(1, broker.Foreground);
        Assert.Equal("2 items of HKLM|64|Git_is1 deleted for good", vm.ResultTitle);
        Assert.Null(vm.ActionInfo);
        Assert.Null(vm.ActionError);
        Assert.Equal(2, reads);
        Assert.False(vm.Busy);
        // A completed delete ends the broker; the page drops its end.
        Assert.True(broker.Disposed);
    }

    [Fact]
    public async Task ADeclinedDeleteNowPromptDeletesNothingAndKeepsTheList()
    {
        var broker = new ScriptedVaultBroker
        {
            Expiring = Held(),
            PurgeError = new BrokerRpcException(-32000, "consent_declined", "declined"),
        };
        var reads = 0;
        var vm = new VaultViewModel(_ => { reads++; return Task.FromResult(GitIndex()); }, _ => Launch(broker));
        await vm.LoadAsync();

        await vm.DeleteNowAsync(GitSession);

        Assert.Equal("Nothing was deleted: the prompt was cancelled.", vm.ActionInfo);
        Assert.Null(vm.ResultTitle);
        Assert.Null(vm.ActionError);
        Assert.Equal(1, reads);
        Assert.False(broker.Disposed);
        Assert.False(vm.Busy);
    }

    [Fact]
    public async Task ACleanupWithNothingInQuarantineIsANoteNotAPrompt()
    {
        var only = Held();
        only.Items.RemoveAll(i => i.Session == GitSession && i.Class == RetentionClass.Quarantine);
        var broker = new ScriptedVaultBroker { Expiring = only };
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(broker));
        await vm.LoadAsync();

        await vm.DeleteNowAsync(GitSession);

        Assert.Empty(broker.PurgeCalls);
        Assert.Equal(0, broker.Foreground);
        Assert.StartsWith("This cleanup has no quarantined files to delete now.", vm.ActionInfo);
        Assert.Null(vm.ResultTitle);
    }

    [Fact]
    public async Task ChooseItemsListsTheCleanupsItemsAndDeletesOneByItsId()
    {
        var broker = new ScriptedVaultBroker { Expiring = Held(), Purge = new PurgeResult { Outcome = Outcome.Complete, Purged = 1 } };
        var second = new ScriptedVaultBroker { Expiring = Held(), Purge = new PurgeResult { Outcome = Outcome.Partial, Purged = 0, Kept = 1 } };
        var brokers = new Queue<ScriptedVaultBroker>([broker, second]);
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(brokers.Dequeue()));
        await vm.LoadAsync();

        // An id the page was not given by the broker starts nothing.
        await vm.DeleteItemNowAsync("e-0000000000000001");
        Assert.Equal(0, broker.ExpiringCalls);

        await vm.ShowItemsAsync(GitSession);

        Assert.Equal(GitSession, vm.ItemsFor);
        Assert.Equal("HKLM|64|Git_is1", vm.ItemsName);
        Assert.Equal(["e-0000000000000001", "e-0000000000000002"], vm.Items.Select(i => i.ExpiryId));
        Assert.Equal(@"C:\Program Files\Git", vm.Items[0].Path);
        var size = LeftoverItemModel.FormatSize(2048);
        Assert.Equal($"{size} · can be put back for 20 more days", vm.Items[0].Detail);
        Assert.Equal($"{size} · user data · can be put back for 20 more days", vm.Items[1].Detail);
        Assert.False(vm.Items[0].Due);
        Assert.Empty(broker.PurgeCalls);
        Assert.Equal(0, broker.Foreground);

        // Not an id of this list: nothing is sent.
        await vm.DeleteItemNowAsync("e-0000000000000004");
        await vm.DeleteItemNowAsync(@"C:\Windows");
        Assert.Empty(broker.PurgeCalls);

        await vm.DeleteItemNowAsync("e-0000000000000001");

        Assert.Equal([["e-0000000000000001"]], broker.PurgeCalls);
        Assert.Equal(1, broker.Foreground);
        Assert.Equal("1 item of HKLM|64|Git_is1 deleted for good", vm.ResultTitle);
        // The deleted item leaves the list; the other stays, with its own "Delete now".
        Assert.Equal(["e-0000000000000002"], vm.Items.Select(i => i.ExpiryId));
        Assert.True(broker.Disposed);

        // The next delete starts a new broker; an item the prompt declined (or the executor kept) stays listed.
        await vm.DeleteItemNowAsync("e-0000000000000002");
        Assert.Equal([["e-0000000000000002"]], second.PurgeCalls);
        Assert.Equal("Nothing was deleted", vm.ResultTitle);
        Assert.Equal("1 kept: you declined them, or they could not be deleted.", vm.ActionInfo);
        Assert.Equal(["e-0000000000000002"], vm.Items.Select(i => i.ExpiryId));

        vm.CloseItems();
        Assert.Null(vm.ItemsFor);
        Assert.Empty(vm.Items);
    }

    [Fact]
    public async Task AnItemThatIsNoLongerListedByTheBrokerClosesTheListAndDeletesNothing()
    {
        var broker = new ScriptedVaultBroker
        {
            Expiring = Held(),
            PurgeError = new BrokerRpcException(-32000, "gone", "gone"),
        };
        var reads = 0;
        var vm = new VaultViewModel(_ => { reads++; return Task.FromResult(GitIndex()); }, _ => Launch(broker));
        await vm.LoadAsync();
        await vm.ShowItemsAsync(GitSession);

        await vm.DeleteItemNowAsync("e-0000000000000001");

        Assert.Null(vm.ItemsFor);
        Assert.Equal("That is no longer in quarantine as listed; nothing was deleted. The list is read again.", vm.ActionInfo);
        Assert.Null(vm.ResultTitle);
        Assert.Equal(2, reads);
    }

    [Fact]
    public async Task NoSecondActionStartsWhileOneRuns()
    {
        var gate = new TaskCompletionSource<VaultBrokerLaunch>();
        var launches = 0;
        var vm = new VaultViewModel(_ => Task.FromResult(GitIndex()), _ => { launches++; return gate.Task; });
        await vm.LoadAsync();

        var first = vm.DeleteNowAsync(GitSession);
        Assert.True(vm.Busy);
        // Every other action is refused while the broker (or its prompt) is busy.
        await vm.DeleteNowAsync(GitSession);
        await vm.ShowItemsAsync(GitSession);
        await vm.RestoreAsync(GitSession);
        await vm.ReviewExpiredAsync();
        Assert.Equal(1, launches);

        gate.SetResult(new VaultBrokerLaunch(null, true, ""));
        await first;
        Assert.False(vm.Busy);
        Assert.True(vm.PromptCancelled);
    }

    private static HistoryIndex GitIndex() => Fixture<HistoryIndex>("stdio.history.index.result.json");

    private static T Fixture<T>(string name) =>
        JsonSerializer.Deserialize<T>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name)))!;

    private static Task<VaultBrokerLaunch> Launch(IVaultBroker broker) =>
        Task.FromResult(new VaultBrokerLaunch(broker, false, ""));

    private sealed class ScriptedVaultBroker : IVaultBroker
    {
        public UndoResult Undo { get; init; } = new();
        public ExpiringList Expiring { get; init; } = new();
        public PurgeResult Purge { get; init; } = new();
        public Exception? UndoError { get; set; }
        public Exception? ExpiringError { get; init; }
        public Exception? PurgeError { get; init; }
        public List<(string, IReadOnlyList<uint>?)> UndoCalls { get; } = [];
        public List<List<string>> PurgeCalls { get; } = [];
        public int ExpiringCalls { get; private set; }
        public int Foreground { get; private set; }
        public bool Disposed { get; private set; }
        public bool IsLive { get; private set; } = true;

        public void AllowForeground() => Foreground++;

        public Task<UndoResult> UndoAsync(string session, IReadOnlyList<uint>? ops, IProgress<Progress>? progress, CancellationToken ct)
        {
            UndoCalls.Add((session, ops));
            return UndoError is { } e ? Task.FromException<UndoResult>(e) : Task.FromResult(Undo);
        }

        /// <summary>Whether each <c>quarantine.expiring</c> asked for the items that are not due.</summary>
        public List<bool> ExpiringFlags { get; } = [];

        public Task<ExpiringList> ExpiringAsync(bool includeNotDue, CancellationToken ct)
        {
            ExpiringCalls++;
            ExpiringFlags.Add(includeNotDue);
            if (ExpiringError is { } e)
            {
                IsLive = false;
                return Task.FromException<ExpiringList>(e);
            }
            // As the broker: an item that is not due is listed only when asked for.
            return Task.FromResult(includeNotDue ? Expiring : new ExpiringList { Items = [.. Expiring.Items.Where(i => i.Due)] });
        }

        public Task<PurgeResult> PurgeAsync(IReadOnlyList<string> expiryIds, CancellationToken ct)
        {
            PurgeCalls.Add([.. expiryIds]);
            return PurgeError is { } e ? Task.FromException<PurgeResult>(e) : Task.FromResult(Purge);
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            IsLive = false;
            return ValueTask.CompletedTask;
        }
    }
}
