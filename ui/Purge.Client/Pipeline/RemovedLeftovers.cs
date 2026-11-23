using Purge.Client.Broker;
using Purge.Client.Rpc;

namespace Purge.Client.Pipeline;

/// <summary>Where a program of the "removed outside Purge" group stands.</summary>
public enum RemovedCheckState
{
    /// <summary>Purge may have stored its fingerprint: "Check for leftovers" is offered.</summary>
    Record,

    /// <summary>Purge did not record what it installed: no button, no broker, no guess-based scan.</summary>
    NoRecord,

    /// <summary>The Windows prompt for the administrator part is up (or the part is starting).</summary>
    Starting,

    /// <summary>The broker is asked <c>leftovers.stored</c>.</summary>
    Checking,

    /// <summary>The broker scans from the stored fingerprint.</summary>
    Scanning,
}

/// <summary>
/// The programs of the "removed outside Purge" group: what <c>inventory.changes</c> listed, less the ones the user has
/// dealt with in this session. A program leaves the group when its "Check for leftovers" finished and reached the
/// Leftovers page, when the user dismisses it, or when Purge itself uninstalled it; the engine is told
/// (<c>inventory.forget</c>), so it does not come back in a later session. A cancelled or failed check keeps it.
/// </summary>
public sealed class RemovedGroup
{
    /// <summary>How many rows the group shows at most; the header counts them all.</summary>
    public const int MaxShown = 5;

    private readonly List<ProgramRef> _programs;
    private readonly Func<IReadOnlyList<string>, Task> _forget;

    /// <param name="disappeared">The <c>inventory.changes</c> answer's <c>disappeared</c> list.</param>
    /// <param name="forget">The engine's <c>inventory.forget</c>; a failure is ignored (display-only state).</param>
    public RemovedGroup(IEnumerable<ProgramRef> disappeared, Func<IReadOnlyList<string>, Task> forget)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        _programs = disappeared.Where(p => seen.Add(p.ProgramId)).ToList();
        _forget = forget;
    }

    /// <summary>How many programs the group still has.</summary>
    public int Count => _programs.Count;

    /// <summary>True when nothing is left: the page hides the group.</summary>
    public bool IsEmpty => _programs.Count == 0;

    /// <summary>The rows to show: the first <see cref="MaxShown"/> still in the group.</summary>
    public IReadOnlyList<ProgramRef> Shown => _programs.Take(MaxShown).ToList();

    /// <summary>Whether <paramref name="programId"/> is still in the group.</summary>
    public bool Contains(string programId) => _programs.Exists(p => p.ProgramId == programId);

    /// <summary>The group's header: the count, and how many are shown when not all are.</summary>
    public string Header(bool live)
    {
        var more = _programs.Count > MaxShown ? $" (showing {MaxShown})" : "";
        return "REMOVED OUTSIDE PURGE · " + _programs.Count.ToString(System.Globalization.CultureInfo.CurrentCulture) + more
               + (live ? "" : "   SAMPLE DATA");
    }

    /// <summary>
    /// Takes <paramref name="programId"/> out of the group and asks the engine to forget it; false (and no engine call)
    /// when it is not in the group.
    /// </summary>
    public bool Acknowledge(string programId)
    {
        var index = _programs.FindIndex(p => p.ProgramId == programId);
        if (index < 0) return false;
        _programs.RemoveAt(index);
        _ = ForgetQuietlyAsync(programId);
        return true;
    }

    private async Task ForgetQuietlyAsync(string programId)
    {
        try { await _forget([programId]).ConfigureAwait(false); }
        catch (Exception e) when (e is not OutOfMemoryException) { }
    }
}

/// <summary>A bar the Programs page shows for the last check.</summary>
public sealed record RemovedNotice(UninstallNoticeKind Kind, string Title, string Message);

/// <summary>
/// A scan from a stored fingerprint, ready for the Leftovers page. <see cref="Session"/> is the live broker link the
/// page takes over (null only from a test's broker).
/// </summary>
public sealed record StoredScanOutcome(string ProgramId, string ProgramName, ScanResult Scan, BrokerSession? Session);

/// <summary>The start of the broker as this check sees it: a live link, or why there is none.</summary>
/// <param name="DeclinedExplanation">
/// With <see cref="UninstallLaunchState.Cancelled"/>: the user chose "Not now" at Purge's explanation, so the Windows
/// prompt was never shown.
/// </param>
public sealed record StoredLeftoversLaunch(UninstallLaunchState State, IStoredLeftoversBroker? Broker, string Message,
    uint? ExitCode = null, bool DeclinedExplanation = false);

/// <summary>
/// "Check for leftovers" on the Programs page's "removed outside Purge" group (M3 design 7a delta 5, section 10 S1).
/// A program whose fingerprint Purge cannot have stored is <see cref="RemovedCheckState.NoRecord"/> from the start
/// (<see cref="FingerprintStore.MayHaveRecord"/>, no prompt); for the others the click starts the elevated broker,
/// asks <c>leftovers.stored</c>, and scans from the stored fingerprint (<c>leftovers.scan {program_id}</c>). Such a
/// scan is always mode <see cref="ScanMode.External"/> (<c>bins/purge-broker/src/scan.rs</c>); when the broker's
/// verify-gone check of the program fails, the forced-mode rule applies inside that mode: nothing is Safe or
/// pre-selected (<c>purge-policy</c> band rules). The scan goes to the Leftovers page through
/// <see cref="Completed"/>, as after an uninstall. No XAML and no process here: the page supplies the probe and the
/// launcher, so every state is testable against scripted ones.
/// </summary>
public sealed class RemovedLeftoversController
{
    private readonly Func<string, bool> _mayHaveRecord;
    private readonly Func<CancellationToken, Task<StoredLeftoversLaunch>> _launch;
    private readonly Dictionary<string, RemovedCheckState> _states = new(StringComparer.Ordinal);
    private readonly object _gate = new();
    private CancellationTokenSource? _cts;
    private bool _busy;
    // Written by the check (any thread), read by the page on the UI thread: volatile, so a read sees the last write.
    private volatile string? _activeProgram;
    private volatile string? _progressText;
    private volatile RemovedNotice? _notice;

    /// <param name="mayHaveRecord">False when Purge surely stored no fingerprint for the id (<see cref="FingerprintStore.MayHaveRecord"/>).</param>
    /// <param name="launch">Starts the elevated broker (the first-elevation explanation and the Windows prompt happen here).</param>
    public RemovedLeftoversController(Func<string, bool> mayHaveRecord, Func<CancellationToken, Task<StoredLeftoversLaunch>> launch)
    {
        _mayHaveRecord = mayHaveRecord;
        _launch = launch;
    }

    /// <summary>Raised after any visible state changed, on the thread that changed it.</summary>
    public event Action? Changed;

    /// <summary>
    /// Raised when the user said No at the Windows prompt, or "Not now" at Purge's explanation (the argument is true
    /// then); the page shows the cancelled bar.
    /// </summary>
    public event Action<bool>? AdminPromptCancelled;

    /// <summary>Raised when the scan is in; the page shows it on the Leftovers page, which takes the broker link.</summary>
    public event Action<StoredScanOutcome>? Completed;

    /// <summary>The program being checked, while a check runs.</summary>
    public string? ActiveProgram
    {
        get => _activeProgram;
        private set => _activeProgram = value;
    }

    /// <summary>The broker's last scan phase, while it scans.</summary>
    public string? ProgressText
    {
        get => _progressText;
        private set => _progressText = value;
    }

    /// <summary>The bar for the last check that did not reach the Leftovers page; null when there is none.</summary>
    public RemovedNotice? Notice
    {
        get => _notice;
        private set => _notice = value;
    }

    /// <summary>True while a check runs; the other rows' buttons wait.</summary>
    public bool IsBusy
    {
        get { lock (_gate) return _busy; }
    }

    /// <summary>Whether the user may dismiss <paramref name="programId"/>: not while its own check runs.</summary>
    public bool CanDismiss(string programId)
    {
        lock (_gate) return !(_busy && ActiveProgram == programId);
    }

    /// <summary>Probes each id once (file system only; call off the UI thread).</summary>
    public void Classify(IEnumerable<string> programIds)
    {
        foreach (var id in programIds)
        {
            lock (_gate)
                if (_states.ContainsKey(id)) continue;
            var state = Probe(id);
            lock (_gate) _states.TryAdd(id, state);
        }
    }

    /// <summary>The state of <paramref name="programId"/>; an id not classified yet is probed now.</summary>
    public RemovedCheckState StateOf(string programId)
    {
        lock (_gate)
            if (_states.TryGetValue(programId, out var known)) return known;
        Classify([programId]);
        lock (_gate) return _states[programId];
    }

    /// <summary>Stops the running check (the broker's <c>$/cancel</c>); the program keeps its button.</summary>
    public void Cancel()
    {
        lock (_gate)
        {
            try { _cts?.Cancel(); }
            catch (ObjectDisposedException) { }
        }
    }

    /// <summary>
    /// The button: for a program with no record it does nothing (no prompt is ever shown for one); otherwise launch,
    /// <c>leftovers.stored</c>, then the scan. One check at a time.
    /// </summary>
    public async Task CheckAsync(string programId, string programName, CancellationToken ct = default)
    {
        CancellationToken token;
        lock (_gate)
        {
            if (_busy) return;
            if (_states.TryGetValue(programId, out var known) && known == RemovedCheckState.NoRecord) return;
        }
        if (StateOf(programId) == RemovedCheckState.NoRecord) return;
        lock (_gate)
        {
            if (_busy) return;
            _busy = true;
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            token = _cts.Token;
        }
        ActiveProgram = programId;
        ProgressText = null;
        Notice = null;
        Set(programId, RemovedCheckState.Starting);
        Raise();

        IStoredLeftoversBroker? broker = null;
        try
        {
            var launch = await _launch(token).ConfigureAwait(false);
            if (launch.State != UninstallLaunchState.Started || launch.Broker is null)
            {
                if (launch.Broker is { } stray) await stray.DisposeAsync().ConfigureAwait(false);
                Set(programId, RemovedCheckState.Record);
                LaunchFailed(launch);
                return;
            }
            broker = launch.Broker;
            token.ThrowIfCancellationRequested();

            Set(programId, RemovedCheckState.Checking);
            Raise();
            var stored = await broker.StoredAsync([programId], token).ConfigureAwait(false);
            if (!stored.Contains(programId, StringComparer.Ordinal))
            {
                Set(programId, RemovedCheckState.NoRecord);
                Notice = NoRecordNotice(programName);
                return;
            }

            Set(programId, RemovedCheckState.Scanning);
            ProgressText = "Starting the scan";
            Raise();
            var scan = await broker.ScanStoredAsync(programId, p =>
            {
                ProgressText = p.Phase;
                Raise();
            }, token).ConfigureAwait(false);

            var session = broker.TakeSession();
            Set(programId, RemovedCheckState.Record);
            Completed?.Invoke(new StoredScanOutcome(programId, programName, scan, session));
        }
        catch (OperationCanceledException)
        {
            Set(programId, RemovedCheckState.Record);
            Notice = new RemovedNotice(UninstallNoticeKind.Info, "Check stopped.", "Nothing was changed.");
        }
        catch (BrokerRpcException e) when (e.Kind == "gone")
        {
            // The broker has no fingerprint for it (removed meanwhile, or another account's program).
            Set(programId, RemovedCheckState.NoRecord);
            Notice = NoRecordNotice(programName);
        }
        catch (BrokerRpcException e)
        {
            Set(programId, RemovedCheckState.Record);
            Notice = new RemovedNotice(UninstallNoticeKind.Error, "The administrator part refused the request.", e.Message);
        }
        catch (BrokerLinkException e)
        {
            Set(programId, RemovedCheckState.Record);
            Notice = new RemovedNotice(UninstallNoticeKind.Error, "The administrator part ended.",
                e.Message + " Nothing was changed; you can check again.");
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            Set(programId, RemovedCheckState.Record);
            Notice = new RemovedNotice(UninstallNoticeKind.Error, "Something went wrong.", e.Message);
        }
        finally
        {
            // After a hand-off this leaves the session to the Leftovers page; otherwise it ends the broker.
            if (broker is not null)
            {
                try { await broker.DisposeAsync().ConfigureAwait(false); }
                catch (Exception e) when (e is not OutOfMemoryException) { }
            }
            ActiveProgram = null;
            ProgressText = null;
            lock (_gate)
            {
                _busy = false;
                _cts?.Dispose();
                _cts = null;
            }
            Raise();
        }
    }

    private void LaunchFailed(StoredLeftoversLaunch launch)
    {
        switch (launch.State)
        {
            case UninstallLaunchState.Cancelled:
                // The shell's cancelled bar says it (error 1223); the program keeps its button for another try.
                AdminPromptCancelled?.Invoke(launch.DeclinedExplanation);
                break;
            case UninstallLaunchState.NotAdministrator:
                Notice = new RemovedNotice(UninstallNoticeKind.Error, "Administrator permission is not available.",
                    launch.Message);
                break;
            default:
                var code = launch.ExitCode is { } c
                    ? $" (exit code {c.ToString(System.Globalization.CultureInfo.InvariantCulture)})"
                    : "";
                Notice = new RemovedNotice(UninstallNoticeKind.Error, "The administrator part could not start.",
                    launch.Message + code);
                break;
        }
    }

    /// <summary>
    /// The bar after an approved prompt that ended without a record (<c>leftovers.stored</c> did not list the program,
    /// or <c>gone</c>): the user said yes to a prompt, so the page says why nothing followed.
    /// </summary>
    private static RemovedNotice NoRecordNotice(string programName) =>
        new(UninstallNoticeKind.Info,
            $"Purge has no record of {(programName.Length > 0 ? programName : "this program")}.",
            "Nothing was scanned or changed.");

    private RemovedCheckState Probe(string programId)
    {
        try { return _mayHaveRecord(programId) ? RemovedCheckState.Record : RemovedCheckState.NoRecord; }
        catch (Exception e) when (e is not OutOfMemoryException) { return RemovedCheckState.Record; }
    }

    private void Set(string programId, RemovedCheckState state)
    {
        lock (_gate) _states[programId] = state;
    }

    private void Raise() => Changed?.Invoke();
}
