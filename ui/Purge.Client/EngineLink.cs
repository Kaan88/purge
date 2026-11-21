using System.ComponentModel;
using Purge.Client.Model;
using Purge.Client.Stdio;

namespace Purge.Client;

/// <summary>What the start of the app needs from the engine: its hello, the program list, and why the sample data stands in.</summary>
/// <param name="Engine">The client to use from now on (the sample client when the engine could not be used).</param>
/// <param name="Error">A sentence for the fallback notice; null when the engine answered (or sample data was asked for).</param>
/// <param name="UiElevated">Whether this process itself runs elevated (the "Administrator" chip).</param>
/// <param name="Changes">The <c>inventory.changes</c> answer, asked before the list (the engine stores the new list when
/// the list ends); null when it could not be asked, and it never faults.</param>
public sealed record StartupResult(IEngineClient Engine, EngineHello Hello, InventoryDoc Inventory, string? Error, bool UiElevated,
    Task<Rpc.InventoryChanges?>? Changes = null);

/// <summary>
/// The engine link of the custom <c>Main</c> (ENGINE_PLAN.md A9.2): starts the engine, sends <c>engine.hello</c> and
/// <c>programs.list</c> on a background thread, and falls back to the sample client with a notice when the engine
/// is missing, cannot start, ends early, answers with an error, or is too slow.
/// </summary>
public sealed class EngineLink
{
    /// <summary>How long the engine has to answer hello and the list before the sample data takes over.</summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);

    private readonly Func<IEngineClient> _fallback;
    private readonly TimeSpan _timeout;
    private readonly Action? _engineReady;
    private readonly Action? _listReply;
    private volatile IEngineClient _client;
    private readonly string? _launchError;
    private readonly bool _sample;

    /// <param name="open">Starts the engine client; may throw when the engine is missing or cannot start.</param>
    /// <param name="fallback">Makes the sample client.</param>
    /// <param name="sample">Use the sample client only: no engine, no notice.</param>
    /// <param name="engineReady">Called after <c>engine.hello</c> is answered (a launch marker).</param>
    /// <param name="listReply">Called after <c>programs.list</c> is answered (a launch marker).</param>
    public EngineLink(Func<IEngineClient> open, Func<IEngineClient> fallback, bool sample = false, TimeSpan? timeout = null,
        Action? engineReady = null, Action? listReply = null)
    {
        _fallback = fallback;
        _sample = sample;
        _timeout = timeout ?? DefaultTimeout;
        _engineReady = engineReady;
        _listReply = listReply;
        if (sample)
        {
            _client = fallback();
        }
        else
        {
            try { _client = open(); }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                _launchError = Describe(e);
                _client = fallback();
            }
        }
        Startup = Task.Run(RunAsync);
    }

    /// <summary>The client in use: the engine, or the sample client after a failure.</summary>
    public IEngineClient Client => _client;

    /// <summary>Hello and the program list; never faults (a failure becomes the sample data with <see cref="StartupResult.Error"/>).</summary>
    public Task<StartupResult> Startup { get; }

    private async Task<StartupResult> RunAsync()
    {
        var elevated = ProcessToken.IsElevated();
        var error = _launchError;
        if (error is null && !_sample)
        {
            try
            {
                using var cts = new CancellationTokenSource(_timeout);
                var engine = _client;
                var hello = await engine.HelloAsync(cts.Token).ConfigureAwait(false);
                _engineReady?.Invoke();
                // Written before the list request, so the engine answers it against the list of the last run.
                var changes = ChangesAsync(engine);
                var doc = await engine.ListProgramsAsync(cts.Token).ConfigureAwait(false);
                _listReply?.Invoke();
                return new StartupResult(engine, hello, doc, null, elevated, changes);
            }
            catch (Exception e) when (e is not OutOfMemoryException)
            {
                error = e is OperationCanceledException ? $"The engine did not answer within {_timeout.TotalSeconds:0} seconds." : Describe(e);
                var broken = _client;
                _client = _fallback();
                await broken.DisposeAsync().ConfigureAwait(false);
            }
        }

        var sampleClient = _client;
        var sampleHello = await sampleClient.HelloAsync().ConfigureAwait(false);
        _engineReady?.Invoke();
        var sampleChanges = ChangesAsync(sampleClient);
        var sampleList = await sampleClient.ListProgramsAsync().ConfigureAwait(false);
        _listReply?.Invoke();
        return new StartupResult(sampleClient, sampleHello, sampleList,
            error is null ? null : "Purge couldn't use its engine, so this list is sample data. " + error, elevated, sampleChanges);
    }

    private static async Task<Rpc.InventoryChanges?> ChangesAsync(IEngineClient engine)
    {
        try { return await engine.GetInventoryChangesAsync().ConfigureAwait(false); }
        catch (Exception e) when (e is not OutOfMemoryException) { return null; }
    }

    private static string Describe(Exception e)
    {
        var text = e switch
        {
            FileNotFoundException => e.Message,
            Win32Exception => "Windows could not start it: " + e.Message,
            _ => e.Message,
        };
        return text.EndsWith('.') ? text : text + ".";
    }
}
