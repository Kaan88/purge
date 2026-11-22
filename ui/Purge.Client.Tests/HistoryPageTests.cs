using System.Text.Json;
using Purge.App.Views;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The History page's view model: the list from <c>history.index</c> (medium engine, no broker), the empty and error
/// states, "Show items" through the broker with the reconcile alert mark per item (review M3-R2 S5), and the alerts
/// of <c>undo.run</c> and <c>journal.resume</c>. The real broker and UAC are VM tests.
/// </summary>
public sealed class HistoryPageTests
{
    private const string GitSession = "20251115T101502Z-9f3a6c1d2b7e4a50";

    [Fact]
    public async Task LoadsEntriesNewestFirstWithoutStartingTheBroker()
    {
        var index = Fixture<HistoryIndex>("stdio.history.index.result.json");
        var newer = Fixture<HistoryIndex>("stdio.history.index.result.json").Sessions[0];
        newer.Id = "20251116T080000Z-0000000000000001";
        newer.Started += TimeSpan.TicksPerDay;
        newer.Owner = new AppRef { ProgramId = "HKLM|64|Git_is1", DisplayName = "Git" };
        newer.State = SessionState.Undone;
        index.Sessions.Add(newer);
        var launches = 0;
        var vm = new HistoryViewModel(_ => Task.FromResult(index), _ => { launches++; return Launch(new ScriptedHistoryBroker()); });

        await vm.LoadAsync();

        Assert.Equal(HistoryPhase.Ready, vm.Phase);
        Assert.Equal(0, launches);
        Assert.Equal(["20251116T080000Z-0000000000000001", GitSession], vm.Sessions.Select(s => s.Id));
        var restored = vm.Sessions[0];
        Assert.Equal("Git", restored.Name);
        Assert.Equal("Restored", restored.State);
        Assert.False(restored.Held);
        var git = vm.Sessions[1];
        Assert.Equal("HKLM|64|Git_is1", git.Name);
        Assert.Equal("Undoable", git.State);
        Assert.Equal(HistoryChip.Undoable, git.Chip);
        Assert.True(git.Held);
        Assert.StartsWith("21 items moved · ", git.Detail);
        Assert.Contains("1 held, in use", git.Detail);
        Assert.False(git.HasAlert);
        Assert.Same(restored, vm.Selected);
        Assert.Null(vm.Items);
    }

    [Fact]
    public async Task AnEmptyIndexShowsTheEmptyState()
    {
        var vm = new HistoryViewModel(_ => Task.FromResult(new HistoryIndex()), _ => Launch(new ScriptedHistoryBroker()));

        await vm.LoadAsync();

        Assert.Equal(HistoryPhase.Empty, vm.Phase);
        Assert.Empty(vm.Sessions);
        Assert.Null(vm.Selected);
        Assert.False(vm.CanRestore);
    }

    [Fact]
    public async Task AnIndexThatCannotBeReadShowsTheError()
    {
        var vm = new HistoryViewModel(_ => Task.FromException<HistoryIndex>(new InvalidDataException("index.json is over the limit")),
            _ => Launch(new ScriptedHistoryBroker()));

        await vm.LoadAsync();

        Assert.Equal(HistoryPhase.Error, vm.Phase);
        Assert.Equal("index.json is over the limit", vm.Error);
        Assert.Empty(vm.Sessions);
    }

    [Fact]
    public async Task ShowItemsStartsTheBrokerAndMarksTheReconcileAlert()
    {
        var broker = new ScriptedHistoryBroker
        {
            Detail = Fixture<HistoryDetail>("pipe.history.get.result.json"),
        };
        var launches = 0;
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => { launches++; return Launch(broker); });
        await vm.LoadAsync();

        await vm.ShowItemsAsync();
        await vm.ShowItemsAsync();

        Assert.Equal(1, launches);
        Assert.Equal([GitSession, GitSession], broker.GetCalls);
        var item = Assert.Single(vm.Items!);
        Assert.True(item.HasAlert);
        Assert.Equal(@"Purge found another file in quarantine and put it back at C:\Program Files\Git.", item.AlertText);
        Assert.Equal("Folder", item.KindText);
        Assert.Equal("Moved to quarantine", item.OutcomeText);
        Assert.True(vm.Selected!.HasAlert);

        // The session's mark stays after the list is read again.
        await vm.LoadAsync();
        Assert.True(vm.Sessions.Single().HasAlert);
        Assert.NotNull(vm.Items);
    }

    [Fact]
    public async Task AnItemWithoutAnAlertHasNoMark()
    {
        var detail = Fixture<HistoryDetail>("pipe.history.get.result.json");
        detail.Items[0].Alert = null;
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(new ScriptedHistoryBroker { Detail = detail }));
        await vm.LoadAsync();

        await vm.ShowItemsAsync();

        Assert.False(Assert.Single(vm.Items!).HasAlert);
        Assert.False(vm.Selected!.HasAlert);
    }

    [Fact]
    public async Task RestoreShowsTheUndoAlertsAndReadsTheListAgain()
    {
        var broker = new ScriptedHistoryBroker
        {
            Detail = Fixture<HistoryDetail>("pipe.history.get.result.json"),
            Undo = new UndoResult
            {
                Outcome = Outcome.Complete,
                Alerts = [new Alert { Op = 1, OriginalPath = @"C:\Program Files\Git", MovedBack = false }],
            },
        };
        var reads = 0;
        var vm = new HistoryViewModel(_ => { reads++; return Task.FromResult(GitIndex()); }, _ => Launch(broker));
        await vm.LoadAsync();
        await vm.ShowItemsAsync();
        vm.Items![0].Checked = true;

        await vm.RestoreAsync(all: false);

        var (undoSession, undoOps) = Assert.Single(broker.UndoCalls);
        Assert.Equal(GitSession, undoSession);
        Assert.Equal([1u], undoOps!);
        Assert.Equal(1, broker.Foreground);
        Assert.Equal("Put back", vm.RestoreTitle);
        Assert.Equal([@"Purge found another file in quarantine and kept it there: C:\Program Files\Git."], vm.RestoreLines);
        Assert.True(vm.Selected!.HasAlert);
        Assert.Equal(2, reads);
        Assert.Equal(2, broker.GetCalls.Count);
        Assert.False(vm.Busy);
    }

    [Fact]
    public async Task RestoreAllSendsNoItemIdsAndADeclinedPromptPutsNothingBack()
    {
        var broker = new ScriptedHistoryBroker
        {
            UndoError = new BrokerRpcException(-32000, "consent_declined", "declined"),
        };
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(broker));
        await vm.LoadAsync();

        await vm.RestoreAsync(all: true);

        Assert.Equal([(GitSession, (IReadOnlyList<uint>?)null)], broker.UndoCalls);
        Assert.Equal("Nothing was put back: the prompt was cancelled.", vm.ActionInfo);
        Assert.Null(vm.RestoreTitle);
    }

    [Fact]
    public async Task ACancelledAdminPromptStartsNothing()
    {
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()),
            _ => Task.FromResult(new HistoryBrokerLaunch(null, true, "")));
        await vm.LoadAsync();

        await vm.ShowItemsAsync();

        Assert.True(vm.PromptCancelled);
        Assert.Null(vm.Items);
        Assert.Null(vm.ActionError);
        Assert.False(vm.Busy);
    }

    [Fact]
    public async Task ABrokerThatDiesIsStartedAgainOnTheNextClick()
    {
        var first = new ScriptedHistoryBroker { GetError = new BrokerLinkException("pipe closed") };
        var second = new ScriptedHistoryBroker { Detail = Fixture<HistoryDetail>("pipe.history.get.result.json") };
        var brokers = new Queue<ScriptedHistoryBroker>([first, second]);
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(brokers.Dequeue()));
        await vm.LoadAsync();

        await vm.ShowItemsAsync();
        Assert.NotNull(vm.ActionError);
        Assert.True(first.Disposed);

        await vm.ShowItemsAsync();
        Assert.Null(vm.ActionError);
        Assert.Single(vm.Items!);
    }

    [Fact]
    public async Task AnInterruptedSessionOffersRecoveryAndShowsItsAlerts()
    {
        var index = GitIndex();
        index.Sessions[0].State = SessionState.Open;
        var broker = new ScriptedHistoryBroker
        {
            Recover = new OutcomeResult
            {
                Outcome = Outcome.Complete,
                Alerts = [new Alert { Op = 1, OriginalPath = @"C:\Program Files\Git", MovedBack = true }],
            },
        };
        var vm = new HistoryViewModel(_ => Task.FromResult(index), _ => Launch(broker));
        await vm.LoadAsync();
        Assert.True(vm.Selected!.Interrupted);
        Assert.Equal("Interrupted", vm.Selected.State);
        Assert.False(vm.CanRestore);

        await vm.RecoverAsync(rollback: true);

        Assert.Equal([(GitSession, true)], broker.RecoverCalls);
        Assert.Equal("Rolled back", vm.RestoreTitle);
        Assert.Equal([@"Purge found another file in quarantine and put it back at C:\Program Files\Git."], vm.RestoreLines);
    }

    [Fact]
    public async Task OpeningThePageNeverAsksForInterruptedSessions()
    {
        var broker = new ScriptedHistoryBroker();
        var launches = 0;
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => { launches++; return Launch(broker); });

        await vm.LoadAsync();

        Assert.Equal(0, launches);
        Assert.Equal(0, broker.PendingCalls);
        Assert.False(vm.Selected!.Interrupted);
    }

    [Fact]
    public async Task CheckForInterruptedListsASessionTheIndexDoesNotHaveAndOffersItsRecovery()
    {
        const string cut = "20251116T090000Z-00000000000000aa";
        var broker = new ScriptedHistoryBroker
        {
            Pending = new PendingList
            {
                Sessions = [new PendingSession { Session = cut, App = "Mozilla Firefox", Done = 37, Total = 52, Started = 134077617020000000 }],
            },
            Recover = new OutcomeResult { Outcome = Outcome.Complete },
        };
        var launches = 0;
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => { launches++; return Launch(broker); });
        await vm.LoadAsync();

        await vm.CheckInterruptedAsync();

        Assert.Equal(1, launches);
        Assert.Equal(1, broker.PendingCalls);
        Assert.Equal([cut, GitSession], vm.Sessions.Select(s => s.Id));
        var found = vm.Selected!;
        Assert.Equal(cut, found.Id);
        Assert.True(found.Interrupted);
        Assert.True(found.FromJournal);
        Assert.Equal("Mozilla Firefox", found.Name);
        Assert.Equal("Interrupted", found.State);
        Assert.Equal("37 of 52 items done · found in the journals", found.Detail);
        Assert.False(found.Held);
        Assert.False(vm.CanRestore);
        Assert.Null(vm.ActionInfo);

        await vm.RecoverAsync(rollback: false);

        Assert.Equal([(cut, false)], broker.RecoverCalls);
        Assert.Equal("Finished", vm.RestoreTitle);
        // Recovered: it is no longer listed from the journal (the index lists it once recovery wrote its entry).
        Assert.DoesNotContain(vm.Sessions, s => s.Id == cut);
        Assert.Equal(1, launches);
    }

    [Fact]
    public async Task CheckForInterruptedMarksAnIndexedSessionWhoseReportWasNeverWritten()
    {
        // The index lists the session as committed; journal.pending lists it (Unindexed: no report).
        var broker = new ScriptedHistoryBroker { Pending = Fixture<PendingList>("pipe.journal.pending.result.json") };
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(broker));
        await vm.LoadAsync();
        Assert.False(vm.Selected!.Interrupted);

        await vm.CheckInterruptedAsync();

        var git = Assert.Single(vm.Sessions);
        Assert.True(git.Interrupted);
        Assert.False(git.FromJournal);
        Assert.Equal("Interrupted", git.State);
        Assert.Equal(HistoryChip.Caution, git.Chip);
    }

    [Fact]
    public async Task CheckForInterruptedSaysSoWhenNothingWasInterrupted()
    {
        var broker = new ScriptedHistoryBroker();
        var vm = new HistoryViewModel(_ => Task.FromResult(new HistoryIndex()), _ => Launch(broker));
        await vm.LoadAsync();

        await vm.CheckInterruptedAsync();

        Assert.Equal(HistoryPhase.Empty, vm.Phase);
        Assert.Equal("No cleanup was interrupted.", vm.ActionInfo);
        Assert.False(vm.Busy);
    }

    [Fact]
    public async Task ARestoreRefusedForRecoveryListsTheInterruptedSessionsWithoutAnotherPrompt()
    {
        const string cut = "20251116T090000Z-00000000000000aa";
        var broker = new ScriptedHistoryBroker
        {
            UndoError = new BrokerRpcException(-32000, "needs_recovery", "an interrupted session comes first"),
            Pending = new PendingList { Sessions = [new PendingSession { Session = cut, App = "Firefox", Started = 1 }] },
        };
        var launches = 0;
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => { launches++; return Launch(broker); });
        await vm.LoadAsync();

        await vm.RestoreAsync(all: true);

        Assert.Equal(1, launches);
        Assert.Equal(1, broker.PendingCalls);
        Assert.Contains("interrupted cleanup comes first", vm.ActionError);
        Assert.Equal(cut, vm.Selected!.Id);
        Assert.True(vm.Selected.Interrupted);
    }

    [Fact]
    public async Task AnotherWriterOfTheStoreIsBusyNotAFailure()
    {
        var broker = new ScriptedHistoryBroker
        {
            UndoError = new BrokerRpcException(-32000, "busy", "a mutating request is running"),
        };
        var vm = new HistoryViewModel(_ => Task.FromResult(GitIndex()), _ => Launch(broker));
        await vm.LoadAsync();

        await vm.RestoreAsync(all: true);

        Assert.Equal("Another Purge window is changing the quarantine. Wait for it to finish, then try again.", vm.ActionError);
        Assert.False(vm.Busy);
    }

    [Fact]
    public async Task TheMediumEngineAnswersHistoryIndex()
    {
        var result = ScriptedEngine.Compact(File.ReadAllText(FixturePath("stdio.history.index.result.json")));
        using var engine = new ScriptedEngine((line, e) =>
            e.Send($"{{\"jsonrpc\":\"2.0\",\"id\":{ScriptedEngine.IdOf(line)},\"result\":{result}}}"));
        await using var client = engine.Client;

        var index = await client.GetHistoryIndexAsync();

        var session = Assert.Single(index.Sessions);
        Assert.Equal(GitSession, session.Id);
        Assert.Equal(21u, session.Counts!.Done);
        Assert.Equal(10737418240UL, Assert.Single(index.Volumes).Cap);
        lock (engine.Requests) Assert.Equal(["history.index"], engine.Requests.Select(ScriptedEngine.MethodOf));
    }

    private static HistoryIndex GitIndex() => Fixture<HistoryIndex>("stdio.history.index.result.json");

    private static string FixturePath(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static T Fixture<T>(string name) =>
        JsonSerializer.Deserialize<T>(File.ReadAllText(FixturePath(name)))!;

    private static Task<HistoryBrokerLaunch> Launch(IHistoryBroker broker) =>
        Task.FromResult(new HistoryBrokerLaunch(broker, false, ""));

    private sealed class ScriptedHistoryBroker : IHistoryBroker
    {
        public HistoryDetail Detail { get; init; } = new();
        public UndoResult Undo { get; init; } = new();
        public OutcomeResult Recover { get; init; } = new();
        public PendingList Pending { get; init; } = new();
        public int PendingCalls { get; private set; }
        public Exception? GetError { get; init; }
        public Exception? UndoError { get; init; }
        public List<string> GetCalls { get; } = [];
        public List<(string, IReadOnlyList<uint>?)> UndoCalls { get; } = [];
        public List<(string, bool)> RecoverCalls { get; } = [];
        public int Foreground { get; private set; }
        public bool Disposed { get; private set; }
        public bool IsLive { get; private set; } = true;

        public void AllowForeground() => Foreground++;

        public Task<HistoryDetail> GetAsync(string session, CancellationToken ct)
        {
            GetCalls.Add(session);
            if (GetError is { } e)
            {
                IsLive = false;
                return Task.FromException<HistoryDetail>(e);
            }
            return Task.FromResult(Detail);
        }

        public Task<UndoResult> UndoAsync(string session, IReadOnlyList<uint>? ops, IProgress<Progress>? progress, CancellationToken ct)
        {
            UndoCalls.Add((session, ops));
            return UndoError is { } e ? Task.FromException<UndoResult>(e) : Task.FromResult(Undo);
        }

        public Task<OutcomeResult> RecoverAsync(string session, bool rollback, CancellationToken ct)
        {
            RecoverCalls.Add((session, rollback));
            return Task.FromResult(Recover);
        }

        public Task<PendingList> PendingAsync(CancellationToken ct)
        {
            PendingCalls++;
            return Task.FromResult(Pending);
        }

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            IsLive = false;
            return ValueTask.CompletedTask;
        }
    }
}
