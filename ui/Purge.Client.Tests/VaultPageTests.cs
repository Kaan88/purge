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
        Assert.Null(vm.ActionError);
        Assert.False(vm.Busy);
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

        public Task<ExpiringList> ExpiringAsync(CancellationToken ct)
        {
            ExpiringCalls++;
            if (ExpiringError is { } e)
            {
                IsLive = false;
                return Task.FromException<ExpiringList>(e);
            }
            return Task.FromResult(Expiring);
        }

        public Task<PurgeResult> PurgeAsync(IReadOnlyList<string> expiryIds, CancellationToken ct)
        {
            PurgeCalls.Add([.. expiryIds]);
            return Task.FromResult(Purge);
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            IsLive = false;
            return ValueTask.CompletedTask;
        }
    }
}
