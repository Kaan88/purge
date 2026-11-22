using System.Collections.Concurrent;
using System.Text.Json;
using Purge.App.Views;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The page models change their state only on the context that drives them (the UI thread in the app), also when
/// the engine or the broker answers on another thread. The views read the models' lists in a render posted through
/// their <c>DispatcherQueue</c>; a model that rewrote a list on a pool thread meanwhile would break that render. A
/// single-thread synchronization context stands for the UI thread here.
/// </summary>
public sealed class UiThreadTests
{
    [Fact]
    public async Task HistoryChangesItsStateOnTheContextThatDrivesIt()
    {
        using var ui = new SingleThreadContext();
        var seen = new ConcurrentBag<int>();
        var broker = new PoolBroker();
        var vm = await ui.RunAsync(() =>
        {
            var model = new HistoryViewModel(_ => OnPool(Fixture<HistoryIndex>("stdio.history.index.result.json")),
                _ => Task.FromResult(new HistoryBrokerLaunch(broker, false, "")));
            model.Changed += () => seen.Add(Environment.CurrentManagedThreadId);
            return Task.FromResult(model);
        });

        await ui.RunAsync(async () =>
        {
            await vm.LoadAsync();
            await vm.ShowItemsAsync();
            await vm.CheckInterruptedAsync();
            return 0;
        });

        Assert.NotEmpty(vm.Items!);
        Assert.True(seen.Count >= 6, $"{seen.Count} changes");
        Assert.All(seen, id => Assert.Equal(ui.ThreadId, id));
    }

    [Fact]
    public async Task VaultChangesItsStateOnTheContextThatDrivesIt()
    {
        using var ui = new SingleThreadContext();
        var seen = new ConcurrentBag<int>();
        var broker = new PoolBroker();
        var vm = await ui.RunAsync(() =>
        {
            var model = new VaultViewModel(_ => OnPool(Fixture<HistoryIndex>("stdio.history.index.result.json")),
                _ => Task.FromResult(new VaultBrokerLaunch(broker, false, "")));
            model.Changed += () => seen.Add(Environment.CurrentManagedThreadId);
            return Task.FromResult(model);
        });

        await ui.RunAsync(async () =>
        {
            await vm.LoadAsync();
            await vm.ReviewExpiredAsync();
            return 0;
        });

        Assert.Equal(1, broker.Purges);
        Assert.True(seen.Count >= 4, $"{seen.Count} changes");
        Assert.All(seen, id => Assert.Equal(ui.ThreadId, id));
    }

    [Fact]
    public async Task LeftoversHandlesABrokerNotificationOnItsOwnContext()
    {
        using var ui = new SingleThreadContext();
        var seen = new ConcurrentBag<int>();
        var broker = new NotifyingBroker();
        var vm = await ui.RunAsync(() =>
        {
            var model = new LeftoversViewModel(broker);
            model.Changed += () => seen.Add(Environment.CurrentManagedThreadId);
            return Task.FromResult(model);
        });

        // The broker's reader thread raises the notification.
        await Task.Run(() => broker.Raise("A1B2-C3D4"));
        var deadline = DateTime.UtcNow.AddSeconds(5);
        while (await ui.RunAsync(() => Task.FromResult(vm.Code)) is null)
        {
            Assert.True(DateTime.UtcNow < deadline, "the notification was never handled");
            await Task.Delay(10);
        }

        Assert.Equal("A1B2-C3D4", vm.Code);
        Assert.NotEmpty(seen);
        Assert.All(seen, id => Assert.Equal(ui.ThreadId, id));
    }

    /// <summary>A result completed on a pool thread, as an engine or broker reader thread completes it.</summary>
    private static Task<T> OnPool<T>(T value) => Task.Run(async () =>
    {
        await Task.Delay(5).ConfigureAwait(false);
        return value;
    });

    private static T Fixture<T>(string name) =>
        JsonSerializer.Deserialize<T>(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name)))!;

    /// <summary>A broker whose every answer completes on a pool thread.</summary>
    private sealed class PoolBroker : IHistoryBroker, IVaultBroker
    {
        public int Purges { get; private set; }
        public bool IsLive => true;
        public void AllowForeground() { }

        public Task<HistoryDetail> GetAsync(string session, CancellationToken ct) =>
            OnPool(Fixture<HistoryDetail>("pipe.history.get.result.json"));

        public Task<UndoResult> UndoAsync(string session, IReadOnlyList<uint>? ops, IProgress<Progress>? progress,
            CancellationToken ct) => OnPool(new UndoResult { Outcome = Outcome.Complete });

        public Task<OutcomeResult> RecoverAsync(string session, bool rollback, CancellationToken ct) =>
            OnPool(new OutcomeResult { Outcome = Outcome.Complete });

        public Task<PendingList> PendingAsync(CancellationToken ct) =>
            OnPool(Fixture<PendingList>("pipe.journal.pending.result.json"));

        public Task<ExpiringList> ExpiringAsync(CancellationToken ct) =>
            OnPool(Fixture<ExpiringList>("pipe.quarantine.expiring.result.json"));

        public Task<PurgeResult> PurgeAsync(IReadOnlyList<string> expiryIds, CancellationToken ct)
        {
            Purges++;
            return OnPool(Fixture<PurgeResult>("pipe.quarantine.purge.result.json"));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    /// <summary>A Leftovers broker that only raises <c>consent.shown</c>.</summary>
    private sealed class NotifyingBroker : ILeftoversBroker
    {
        public event Action<ConsentShown>? ConsentShown;

        public event Action<BaselineChanged>? BaselineChanged
        {
            add { }
            remove { }
        }

        public bool IsLive => true;

        public void Raise(string code) => ConsentShown?.Invoke(new ConsentShown { Code = code, Request = 1 });

        public Task<ScanResult> ScanSessionAsync(string sessionId, bool forced, IProgress<Progress>? progress, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<ScanResult> ScanStoredAsync(string programId, IProgress<Progress>? progress, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<CandidatesPage> CandidatesAsync(string scanId, uint offset, int limit, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<Explanation> ExplainAsync(string scanId, string candidateId, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<PlanCreated> CreatePlanAsync(string scanId, IReadOnlyList<string> selected, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<ExecResult> ExecuteAsync(string planId, RestorePoint restorePoint, IProgress<Progress>? progress,
            CancellationToken ct) => throw new NotSupportedException();

        public Task<UndoResult> UndoAsync(string session, IProgress<Progress>? progress, CancellationToken ct) =>
            throw new NotSupportedException();

        public Task<OutcomeResult> RetryHeldAsync(string session, CancellationToken ct) =>
            throw new NotSupportedException();
    }
}

/// <summary>
/// A synchronization context with one thread of its own, standing for the UI thread: everything posted to it runs on
/// that thread, in order.
/// </summary>
internal sealed class SingleThreadContext : SynchronizationContext, IDisposable
{
    private readonly BlockingCollection<(SendOrPostCallback Callback, object? State)> _queue = new();
    private readonly Thread _thread;

    public SingleThreadContext()
    {
        _thread = new Thread(() =>
        {
            SetSynchronizationContext(this);
            foreach (var (callback, state) in _queue.GetConsumingEnumerable()) callback(state);
        })
        { IsBackground = true, Name = "test UI thread" };
        _thread.Start();
    }

    public int ThreadId => _thread.ManagedThreadId;

    public override void Post(SendOrPostCallback d, object? state)
    {
        if (!_queue.IsAddingCompleted) _queue.Add((d, state));
    }

    public override void Send(SendOrPostCallback d, object? state) => throw new NotSupportedException();

    public override SynchronizationContext CreateCopy() => this;

    /// <summary>Runs <paramref name="body"/> on the context's thread and gives its result.</summary>
    public Task<T> RunAsync<T>(Func<Task<T>> body)
    {
        var done = new TaskCompletionSource<T>(TaskCreationOptions.RunContinuationsAsynchronously);
        Post(async _ =>
        {
            try { done.SetResult(await body()); }
            catch (Exception e) { done.SetException(e); }
        }, null);
        return done.Task;
    }

    public void Dispose() => _queue.CompleteAdding();
}
