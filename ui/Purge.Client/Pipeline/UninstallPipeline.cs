using System.Text.Json;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using Purge.Client.Stdio;

namespace Purge.Client.Pipeline;

/// <summary>The five steps of the Uninstall pipeline page (M3_DESIGN.md §10, "Uninstall pipeline").</summary>
public enum UninstallStep
{
    /// <summary><c>uninstall.prepare</c>: the broker records what the program registered.</summary>
    Record,

    /// <summary>The program's own uninstaller, in the broker or at the user's level.</summary>
    Run,

    /// <summary>Verify-gone: the broker's own check that the program left.</summary>
    CheckGone,

    /// <summary><c>leftovers.scan</c> over the session.</summary>
    FindLeftovers,

    /// <summary>The scan is in; the leftovers page takes over.</summary>
    Ready,
}

/// <summary>How one step of the stepper stands.</summary>
public enum StepState
{
    Pending,
    Active,
    Done,
    Warning,
    Failed,
}

/// <summary>Why the pipeline shows a bar.</summary>
public enum UninstallNoticeKind
{
    Info,
    Warning,
    Error,
}

/// <summary>
/// One line the page shows: the cancelled prompt, an exit code with the forced cleanup and Retry, still installed, a
/// restart, or a link that ended. <see cref="ExitCode"/> is the uninstaller's, when it gave one.
/// </summary>
public sealed record UninstallNotice(UninstallNoticeKind Kind, string Title, string Message, uint? ExitCode = null,
    bool CanRetry = false, bool CanForce = false, bool CanStartOver = false);

/// <summary>What the Uninstall click asked for: one program (the queue runs one after the other).</summary>
public sealed record UninstallTarget(string ProgramId, string ProgramName);

/// <summary>The answer the leftovers page needs after the pipeline ends.</summary>
public sealed record UninstallOutcome(UninstallTarget Target, string SessionId, string ScanId, ScanMode Mode, bool Quiet,
    RestorePoint RestorePoint)
{
    /// <summary>True for the forced scan after a failed or unverified uninstall: nothing starts ticked.</summary>
    public bool Forced => Mode == ScanMode.Forced;
}

/// <summary>
/// The confirm dialog's content: the steps, the exact command and its signer, the quiet choice and the restore-point
/// choice. The command is the one that will run, taken from the process that runs it.
/// </summary>
public sealed record UninstallConfirmation(UninstallTarget Target, IReadOnlyList<string> Steps, string Command,
    string? QuietCommand, string? Signer, bool QuietAvailable, bool Quiet, RestorePoint RestorePoint,
    IReadOnlyList<RunningProcess> Running);

/// <summary>How the click's answer is decided: go on, stop, or check the running processes again.</summary>
public sealed record UninstallAnswer(bool Proceed, bool Quiet, RestorePoint RestorePoint, bool Recheck = false);

/// <summary>How the elevated broker's start went, mapped from <see cref="BrokerLaunchResult"/> for the page.</summary>
public enum UninstallLaunchState
{
    Started,
    Cancelled,
    NotAdministrator,
    CannotStart,
    Failed,
}

/// <summary>The start of the broker as the pipeline sees it: a live link, or why there is none.</summary>
/// <param name="DeclinedExplanation">
/// With <see cref="UninstallLaunchState.Cancelled"/>: the user chose "Not now" at Purge's explanation, so the Windows
/// prompt was never shown (the shell's bar must not say it was cancelled).
/// </param>
public sealed record UninstallLaunch(UninstallLaunchState State, IUninstallBroker? Broker, string Message, uint? ExitCode = null,
    bool DeclinedExplanation = false);

/// <summary>The broker side of the Uninstall pipeline: the four requests of design 3.2 and 6.3.</summary>
public interface IUninstallBroker : IAsyncDisposable
{
    /// <summary>The broker's consent dialog is up (<c>consent.shown</c>); the code is the one in its footer.</summary>
    event Action<ConsentShown>? ConsentShown;

    Task<PrepareResult> PrepareAsync(IReadOnlyList<string> programIds, Action<Progress>? progress, CancellationToken ct);

    /// <summary>
    /// <c>uninstall.run</c>. The broker asks its own dialog first and answers <c>consent_declined</c> when it is
    /// declined; <paramref name="restorePoint"/> is shown in that dialog.
    /// </summary>
    Task<RunResult> RunAsync(string sessionId, bool quiet, RestorePoint restorePoint, Action<Progress>? progress,
        CancellationToken ct);

    Task<ObservedResult> ObservedAsync(string sessionId, RunOutcome? outcome, CancellationToken ct);

    Task<ScanResult> ScanAsync(string sessionId, bool forced, Action<Progress>? progress, CancellationToken ct);
}

/// <summary>The medium engine's side: <c>uninstall.route</c> and <c>uninstall.run_user</c>.</summary>
public interface IMediumUninstall
{
    Task<RouteInfo> RouteAsync(string programId, CancellationToken ct);

    Task<RunUserResult> RunUserAsync(string programId, bool quiet, Action<Progress>? progress, CancellationToken ct);
}

/// <summary>
/// The broker's uninstall methods over a checked <see cref="BrokerSession"/> (its <c>engine.hello</c>, design 3.3 step 6,
/// was answered when the session was made); progress notifications feed the current call only, and a lost client does
/// not stop the broker's run.
/// </summary>
public sealed class BrokerUninstallClient : IUninstallBroker
{
    private readonly BrokerSession _session;
    private readonly object _progressGate = new();
    private Action<Progress>? _progress;
    private int _disposed;
    private int _handedOver;

    public BrokerUninstallClient(BrokerSession session)
    {
        _session = session;
        session.Rpc.Notification += OnNotification;
    }

    /// <summary>The live link, for the leftovers page once the pipeline hands over.</summary>
    public BrokerSession Session => _session;

    /// <summary>
    /// Hands the session to the leftovers page: from here the session is not closed by this wrapper and the progress
    /// subscription is gone. Null on a second call.
    /// </summary>
    public BrokerSession? TakeSession()
    {
        if (Interlocked.Exchange(ref _handedOver, 1) != 0) return null;
        _session.Rpc.Notification -= OnNotification;
        return _session;
    }

    public event Action<ConsentShown>? ConsentShown;

    private void OnNotification(BrokerNotification notification)
    {
        if (notification.Method == "consent.shown")
        {
            try
            {
                if (notification.Params.Deserialize(RpcJsonContext.Default.ConsentShown) is { } shown)
                    ConsentShown?.Invoke(shown);
            }
            catch (Exception e) when (e is JsonException or InvalidOperationException) { }
            return;
        }
        if (notification.Method is not ("prepare.progress" or "uninstall.progress" or "scan.progress")) return;
        Progress? progress;
        try { progress = notification.Params.Deserialize(RpcJsonContext.Default.Progress); }
        catch (JsonException) { return; }
        if (progress is null) return;
        Action<Progress>? handler;
        lock (_progressGate) handler = _progress;
        try { handler?.Invoke(progress); }
        catch (Exception e) when (e is not OutOfMemoryException) { }
    }

    public Task<PrepareResult> PrepareAsync(IReadOnlyList<string> programIds, Action<Progress>? progress, CancellationToken ct) =>
        Send("uninstall.prepare", new ProgramsParams { ProgramIds = [.. programIds] }, RpcJsonContext.Default.ProgramsParams,
            RpcJsonContext.Default.PrepareResult, progress, ct);

    public Task<RunResult> RunAsync(string sessionId, bool quiet, RestorePoint restorePoint, Action<Progress>? progress,
        CancellationToken ct)
    {
        // The broker's dialog is drawn by another process: let it come to the front.
        _session.AllowForeground();
        return Send("uninstall.run", new RunParams { SessionId = sessionId, Quiet = quiet, RestorePoint = restorePoint },
            RpcJsonContext.Default.RunParams, RpcJsonContext.Default.RunResult, progress, ct);
    }

    public Task<ObservedResult> ObservedAsync(string sessionId, RunOutcome? outcome, CancellationToken ct) =>
        Send("uninstall.observed", new ObservedParams { SessionId = sessionId, Outcome = outcome },
            RpcJsonContext.Default.ObservedParams, RpcJsonContext.Default.ObservedResult, null, ct);

    public Task<ScanResult> ScanAsync(string sessionId, bool forced, Action<Progress>? progress, CancellationToken ct) =>
        Send("leftovers.scan", new LeftoversScanParams { SessionId = sessionId, Forced = forced },
            RpcJsonContext.Default.LeftoversScanParams, RpcJsonContext.Default.ScanResult, progress, ct);

    private async Task<T> Send<TParams, T>(string method, TParams parameters,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<TParams> paramsInfo,
        System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> resultInfo, Action<Progress>? progress, CancellationToken ct)
        where TParams : notnull
    {
        lock (_progressGate) _progress = progress;
        try
        {
            return await _session.Rpc.CallAsync(method, parameters, paramsInfo, resultInfo, ct).ConfigureAwait(false);
        }
        finally
        {
            lock (_progressGate) _progress = null;
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        _session.Rpc.Notification -= OnNotification;
        // A session handed to the leftovers page belongs to that page now.
        if (Volatile.Read(ref _handedOver) == 0)
            await _session.DisposeAsync().ConfigureAwait(false);
    }
}

/// <summary><see cref="IMediumUninstall"/> over the app's one medium engine.</summary>
public sealed class EngineMediumUninstall(IEngineClient engine) : IMediumUninstall
{
    public Task<RouteInfo> RouteAsync(string programId, CancellationToken ct) =>
        engine.GetUninstallRouteAsync(programId, ct);

    public Task<RunUserResult> RunUserAsync(string programId, bool quiet, Action<Progress>? progress, CancellationToken ct) =>
        engine.RunUserUninstallAsync(programId, quiet, progress, ct);
}

/// <summary>
/// The Uninstall pipeline's view model (M3-UI-S2): launch the broker on the click, prepare, confirm, run the
/// program's own uninstaller on its route, check it is gone, scan, then hand the scan to the leftovers page. It
/// holds no XAML and no process: the page supplies the launcher and the two links, so every state and every error is
/// testable against scripted ones.
/// </summary>
public sealed class UninstallController : IAsyncDisposable
{
    /// <summary>The five steps in the order the page lists them.</summary>
    public static readonly IReadOnlyList<UninstallStep> Steps =
        [UninstallStep.Record, UninstallStep.Run, UninstallStep.CheckGone, UninstallStep.FindLeftovers, UninstallStep.Ready];

    private const string Guide = "Purge records the program, runs the program's own uninstaller, checks that it is gone, "
                                 + "then scans for what it left.";

    private readonly Func<CancellationToken, Task<UninstallLaunch>> _launch;
    private readonly IMediumUninstall _medium;
    private readonly Dictionary<UninstallStep, (StepState State, string? Detail)> _stepStates = [];
    private readonly List<UninstallNotice> _notices = [];

    private IUninstallBroker? _broker;
    private Prepared? _prepared;
    private TaskCompletionSource<UninstallAnswer>? _answer;
    private UninstallStep? _activeStep;
    private RetryStage _retry;
    private bool _force;
    private bool _busy;
    private bool _detached;
    private int _disposed;

    private enum RetryStage
    {
        None,
        Prepare,
        Run,
        Scan,
    }

    /// <param name="launch">Starts the elevated broker (the first-elevation explanation and the UAC prompt happen here).</param>
    /// <param name="medium">The medium engine's route and run_user calls.</param>
    public UninstallController(Func<CancellationToken, Task<UninstallLaunch>> launch, IMediumUninstall medium)
    {
        _launch = launch;
        _medium = medium;
        foreach (var step in Steps) _stepStates[step] = (StepState.Pending, null);
    }

    /// <summary>Raised after any visible state changed, on the caller's thread.</summary>
    public event Action? Changed;

    /// <summary>Raised when the confirm dialog has to be shown; answer it with <see cref="AnswerAsync"/>.</summary>
    public event Action<UninstallConfirmation>? ConfirmationRequested;

    /// <summary>Raised when the scan is in. The page then shows the leftovers page with <see cref="Completed"/>.</summary>
    public event Action<UninstallOutcome>? Completed;

    /// <summary>
    /// Raised when the uninstaller ran and the broker checked the program, before the leftover scan. The flag is true
    /// when the uninstaller succeeded and the broker confirmed the program gone: Purge removed it, so the Programs page
    /// drops it and the engine forgets it (it is never "removed outside Purge"). Either way the list is read again.
    /// </summary>
    public event Action<UninstallTarget, bool>? RunEnded;

    /// <summary>
    /// Raised when the user said No at the Windows prompt, or "Not now" at Purge's explanation (the argument is true
    /// then); the page shows the cancelled bar.
    /// </summary>
    public event Action<bool>? AdminPromptCancelled;

    public UninstallTarget? Target { get; private set; }

    /// <summary>The step the stepper marks as current (the active or the last finished one).</summary>
    public UninstallStep CurrentStep { get; private set; } = UninstallStep.Record;

    public UninstallLaunchState? LaunchState { get; private set; }

    /// <summary>"Administrator" or "This user's level", once the route is known.</summary>
    public string? RouteText { get; private set; }

    /// <summary>The command for the current quiet choice: the one the run will use.</summary>
    public string? SelectedCommand => Quiet && QuietAvailable ? QuietCommand : Command;

    public string? Command { get; private set; }

    public string? QuietCommand { get; private set; }

    public string? Signer { get; private set; }

    public IReadOnlyList<RunningProcess> Running { get; private set; } = [];

    public bool QuietAvailable { get; private set; }

    public bool Quiet { get; private set; }

    /// <summary>The restore-point choice carried to the leftovers page's <c>plan.execute</c>.</summary>
    public RestorePoint RestorePoint { get; private set; } = RestorePoint.HighRisk;

    /// <summary>Every bar of this run, newest last; an <see cref="UninstallNoticeKind.Error"/> one blocks the run.</summary>
    public IReadOnlyList<UninstallNotice> Notices => _notices;

    /// <summary>The scan and its ids once the pipeline ended; null before.</summary>
    public UninstallOutcome? CompletedOutcome { get; private set; }

    /// <summary>The broker link, for the page that takes it over; null after <see cref="TakeBroker"/> or a failure.</summary>
    public IUninstallBroker? Broker => _broker;

    public bool IsBusy => _busy;

    public string GuideText => Guide;

    public StepState StateOf(UninstallStep step) => _stepStates[step].State;

    public string? DetailOf(UninstallStep step) => _stepStates[step].Detail;

    /// <summary>Starts the pipeline for one program. A second call while one runs is ignored.</summary>
    public async Task BeginAsync(UninstallTarget target, CancellationToken ct = default)
    {
        if (_busy) return;
        await GuardAsync(async () =>
        {
            Reset(target);
            if (await GatherAndConfirmAsync(ct).ConfigureAwait(false))
                await RunStageAsync(ct).ConfigureAwait(false);
        }, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// The confirm dialog's answer. A "check again" re-reads the commands and the running processes and asks again;
    /// "not now" stops with nothing changed. It is not a request of its own: it only releases the waiting pipeline.
    /// </summary>
    public Task AnswerAsync(UninstallAnswer answer)
    {
        var waiting = _answer;
        if (waiting is null) return Task.CompletedTask;
        if (answer.Recheck)
        {
            _answer = null;
            waiting.TrySetResult(answer);
            return Task.CompletedTask;
        }
        if (!answer.Proceed)
        {
            _answer = null;
            waiting.TrySetResult(answer);
            AddNotice(new UninstallNotice(UninstallNoticeKind.Info, "Uninstall cancelled.",
                "Nothing was changed. The program was only recorded."));
            Raise();
            return Task.CompletedTask;
        }
        Quiet = answer.Quiet && QuietAvailable;
        RestorePoint = answer.RestorePoint;
        _answer = null;
        waiting.TrySetResult(answer);
        return Task.CompletedTask;
    }

    /// <summary>The Retry of a bar: the run again, the scan again, or the whole preparation again.</summary>
    public Task RetryAsync() => GuardAsync(async () =>
    {
        ClearErrors();
        StageRerun();
        switch (_retry)
        {
            case RetryStage.Run:
                _retry = RetryStage.None;
                await RunStageAsync(CancellationToken.None).ConfigureAwait(false);
                break;
            case RetryStage.Scan:
                _retry = RetryStage.None;
                await FindLeftoversAsync(_force, CancellationToken.None).ConfigureAwait(false);
                break;
            default:
                await RestartAsync(CancellationToken.None).ConfigureAwait(false);
                break;
        }
    }, CancellationToken.None);

    /// <summary>The safety-net choices of the page before the confirmation is answered.</summary>
    public void SetChoice(bool quiet, RestorePoint restorePoint)
    {
        if (QuietAvailable) Quiet = quiet;
        RestorePoint = restorePoint;
        Raise();
    }

    /// <summary>
    /// The running-process line's Retry: re-reads the commands and the processes that hold the program, then asks
    /// again. At the confirm dialog it releases it with a recheck; later it records the program again.
    /// </summary>
    public async Task RecheckAsync()
    {
        var waiting = _answer;
        if (waiting is not null)
        {
            _answer = null;
            waiting.TrySetResult(new UninstallAnswer(false, Quiet, RestorePoint, Recheck: true));
            return;
        }
        if (Target is null || _prepared is null) return;
        await GuardAsync(async () =>
        {
            StageRerun();
            _prepared = null;
            ClearSteps();
            SetStep(UninstallStep.Record, StepState.Pending, null);
            if (await GatherAndConfirmAsync(CancellationToken.None).ConfigureAwait(false))
                await RunStageAsync(CancellationToken.None).ConfigureAwait(false);
        }, CancellationToken.None).ConfigureAwait(false);
    }

    /// <summary>"Run forced cleanup": scan this session in the forced mode with nothing pre-selected.</summary>
    public Task ForceAsync() => GuardAsync(async () =>
    {
        ClearErrors();
        StageRerun();
        _force = true;
        _retry = RetryStage.None;
        if (StateOf(UninstallStep.CheckGone) is StepState.Pending or StepState.Active)
        {
            // A broker-route run that failed never carried a verify-gone. The scan is forced either way.
            SetStep(UninstallStep.CheckGone, StepState.Warning, "Not checked: the uninstaller failed");
        }
        await FindLeftoversAsync(true, CancellationToken.None).ConfigureAwait(false);
    }, CancellationToken.None);

    /// <summary>Starts again from the broker: a dead link is closed and a fresh one is launched (UAC again).</summary>
    public Task StartOverAsync() => GuardAsync(async () =>
    {
        ClearErrors();
        await RestartAsync(CancellationToken.None).ConfigureAwait(false);
    }, CancellationToken.None);

    private async Task RestartAsync(CancellationToken ct)
    {
        await DropBrokerAsync().ConfigureAwait(false);
        var target = Target;
        if (target is null) return;
        Reset(target);
        if (await GatherAndConfirmAsync(ct).ConfigureAwait(false))
            await RunStageAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// A stage runs again (Retry, Check again, Run forced cleanup): the scan from before is no longer this run's, so
    /// <see cref="CompletedOutcome"/> is cleared until the new scan is in. A page that holds the old scan for the
    /// leftovers page must not hand it over (with the broker this run is using) meanwhile.
    /// </summary>
    private void StageRerun()
    {
        CompletedOutcome = null;
        Raise();
    }

    /// <summary>Hands the live broker to the leftovers page. The controller no longer closes it.</summary>
    public IUninstallBroker? TakeBroker()
    {
        _detached = true;
        var broker = _broker;
        _broker = null;
        return broker;
    }

    private async Task<bool> GatherAndConfirmAsync(CancellationToken ct)
    {
        if (!await EnsureBrokerAsync(ct).ConfigureAwait(false)) return false;

        while (true)
        {
            if (_prepared is null || StateOf(UninstallStep.Record) != StepState.Done)
            {
                await PrepareAsync(ct).ConfigureAwait(false);
                if (_prepared is null) return false;
            }

            var confirmation = BuildConfirmation();
            var answer = await AskAsync(confirmation, ct).ConfigureAwait(false);
            if (answer.Recheck)
            {
                // Re-read both sides: a process may have closed and the command may differ now.
                _prepared = null;
                ClearSteps();
                SetStep(UninstallStep.Record, StepState.Pending, null);
                continue;
            }
            if (!answer.Proceed)
            {
                CurrentStep = UninstallStep.Run;
                return false;
            }
            Quiet = answer.Quiet && QuietAvailable;
            RestorePoint = answer.RestorePoint;
            return true;
        }
    }

    private async Task<bool> EnsureBrokerAsync(CancellationToken ct)
    {
        if (_broker is not null) return true;
        SetStep(UninstallStep.Record, StepState.Active, "Starting the administrator part");
        var launch = await _launch(ct).ConfigureAwait(false);
        LaunchState = launch.State;
        switch (launch.State)
        {
            case UninstallLaunchState.Started when launch.Broker is not null:
                _broker = launch.Broker;
                return true;
            case UninstallLaunchState.Cancelled:
                // "Not now" at the explanation and No at the Windows prompt both end here: the words fit either.
                SetStep(UninstallStep.Record, StepState.Failed, "Administrator permission was not given");
                AddNotice(new UninstallNotice(UninstallNoticeKind.Info, "Administrator permission was not given.",
                    "Nothing was changed. Uninstalling needs administrator permission."));
                AdminPromptCancelled?.Invoke(launch.DeclinedExplanation);
                return false;
            case UninstallLaunchState.NotAdministrator:
                SetStep(UninstallStep.Record, StepState.Failed, "An administrator account is needed");
                AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "Administrator permission is not available.",
                    launch.Message));
                return false;
            default:
                SetStep(UninstallStep.Record, StepState.Failed, "The administrator part did not start");
                AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "The administrator part could not start.",
                    ExitText(launch.Message, launch.ExitCode), launch.ExitCode, CanStartOver: true));
                return false;
        }
    }

    private async Task PrepareAsync(CancellationToken ct)
    {
        var target = Target!;
        SetStep(UninstallStep.Record, StepState.Active, RecordPhaseText(null));
        var prepared = await _broker!.PrepareAsync([target.ProgramId],
            p => SetStep(UninstallStep.Record, StepState.Active, RecordPhaseText(p.Phase)), ct).ConfigureAwait(false);
        var program = prepared.Programs.Count > 0 ? prepared.Programs[0] : null;
        if (program is null)
            throw new InvalidDataException("The administrator part recorded no program.");
        _prepared = program;

        Command = program.Command;
        QuietCommand = program.QuietCommand;
        Signer = program.Signer;
        Running = program.Running;
        RouteText = program.Route == Route.Broker ? "Administrator" : "This user's level";

        if (program.Route == Route.Medium)
        {
            // The command shown must be the one the medium engine will run: its own inventory, its own rules.
            var info = await _medium.RouteAsync(target.ProgramId, ct).ConfigureAwait(false);
            if (info.Route != Route.Medium)
            {
                SetStep(UninstallStep.Record, StepState.Failed, "The two parts disagree about the route");
                FailWrongRoute(info.Route);
                _prepared = null;
                return;
            }
            Command = info.Command;
            QuietCommand = info.QuietCommand;
            Signer = info.Signer;
            Running = info.Running;
            RouteText = "This user's level";
        }

        QuietAvailable = !string.IsNullOrEmpty(QuietCommand);
        Quiet = QuietAvailable;
        SetStep(UninstallStep.Record, StepState.Done,
            program.Route == Route.Medium ? "Recorded; its uninstaller runs at your level" : "Recorded by the administrator part");
        SetStep(UninstallStep.Run, StepState.Pending, null);
        CurrentStep = UninstallStep.Run;
        Raise();
    }

    /// <summary>
    /// The Record step's line for one broker harvest phase. The phases are the engine's own log lines; the longest is
    /// the snapshot of the PC taken before the uninstaller runs (about 10 to 20 seconds on a full PC, the same for any
    /// program), so it says what it is for and how long it takes instead of sitting on a technical line (user feedback:
    /// the first step "takes too long").
    /// </summary>
    public static string RecordPhaseText(string? phase) => phase switch
    {
        null => "Recording what the program registered",
        _ when phase.StartsWith("harvest: reading roots", StringComparison.Ordinal) =>
            "Taking a snapshot of this PC to compare with after the uninstall. This usually takes 10 to 20 seconds.",
        _ when phase.StartsWith("loading the baseline", StringComparison.Ordinal)
               || phase.StartsWith("baseline view", StringComparison.Ordinal) =>
            "Loading what a clean Windows looks like",
        _ when phase.StartsWith("harvest: reading the inventory", StringComparison.Ordinal)
               || phase.Contains(" entries; target ", StringComparison.Ordinal) => "Finding the program",
        _ => "Recording what the program registered",
    };

    private UninstallConfirmation BuildConfirmation()
    {
        var steps = new List<string>
        {
            "Record what the program registered",
            _prepared?.Route == Route.Medium ? "Run its uninstaller at your level" : "Run its uninstaller as administrator",
            "Check that it is gone",
            "Find its leftovers",
            "Review the list before anything moves",
        };
        return new UninstallConfirmation(Target!, steps, SelectedCommand ?? "", QuietCommand, Signer, QuietAvailable,
            Quiet && QuietAvailable, RestorePoint, Running);
    }

    private async Task<UninstallAnswer> AskAsync(UninstallConfirmation confirmation, CancellationToken ct)
    {
        var answer = new TaskCompletionSource<UninstallAnswer>(TaskCreationOptions.RunContinuationsAsynchronously);
        _answer = answer;
        ConfirmationRequested?.Invoke(confirmation);
        return await answer.Task.WaitAsync(ct).ConfigureAwait(false);
    }

    private async Task RunStageAsync(CancellationToken ct)
    {
        if (_prepared is null) return;
        if (_prepared.Route == Route.Medium) await RunMediumAsync(ct).ConfigureAwait(false);
        else await RunBrokerAsync(ct).ConfigureAwait(false);
    }

    private async Task RunBrokerAsync(CancellationToken ct)
    {
        // The broker asks its own dialog before it starts anything: wait for it, and say nothing has run.
        SetStep(UninstallStep.Run, StepState.Active, "Waiting for the Purge security prompt. Nothing has run yet.");
        CurrentStep = UninstallStep.Run;
        Raise();
        var broker = _broker!;
        void PromptShown(ConsentShown shown)
        {
            SetStep(UninstallStep.Run, StepState.Active,
                $"Confirm in the Purge security prompt (code {shown.Code}). Nothing has run yet.");
            Raise();
        }
        RunResult result;
        broker.ConsentShown += PromptShown;
        try
        {
            result = await broker.RunAsync(_prepared!.SessionId, Quiet, RestorePoint,
                p => SetStep(UninstallStep.Run, StepState.Active, p.Phase), ct).ConfigureAwait(false);
        }
        catch (BrokerRpcException e) when (e.Kind == "consent_declined")
        {
            SetStep(UninstallStep.Run, StepState.Warning, "Not started: the security prompt was declined");
            _retry = RetryStage.Run;
            AddNotice(new UninstallNotice(UninstallNoticeKind.Info, "You declined in the Purge security prompt.",
                "Nothing was run. The program was only recorded. You can ask again.", CanRetry: true));
            return;
        }
        catch (BrokerRpcException e) when (e.Kind == "uninstall_failed")
        {
            SetStep(UninstallStep.Run, StepState.Failed, ExitDetail(e.Details?.ExitCode, Quiet));
            OnUninstallFailed(e.Details?.ExitCode, e.Message);
            return;
        }
        catch (BrokerRpcException e) when (e.Kind == "wrong_route")
        {
            SetStep(UninstallStep.Run, StepState.Failed, "The wrong part was asked");
            FailWrongRoute(e.Details?.Route ?? Route.Medium);
            return;
        }
        finally
        {
            broker.ConsentShown -= PromptShown;
        }
        SetStep(UninstallStep.Run, StepState.Done, ExitDetail(result.ExitCode, Quiet));
        await CheckBrokerGoneAsync(result, ct).ConfigureAwait(false);
    }

    private async Task RunMediumAsync(CancellationToken ct)
    {
        var target = Target!;
        SetStep(UninstallStep.Run, StepState.Active, Quiet ? "Running its quiet uninstaller" : "Running its uninstaller");
        CurrentStep = UninstallStep.Run;
        Raise();
        RunUserResult result;
        try
        {
            result = await _medium.RunUserAsync(target.ProgramId, Quiet,
                p => SetStep(UninstallStep.Run, StepState.Active, p.Phase), ct).ConfigureAwait(false);
        }
        catch (EngineRpcException e) when (e.Kind == "wrong_route")
        {
            FailWrongRoute(Route.Broker);
            return;
        }
        var failed = result.Outcome is RunOutcome.Failed or RunOutcome.TimedOut or RunOutcome.Cancelled;
        SetStep(UninstallStep.Run, failed ? StepState.Failed : StepState.Done, ExitDetail(result.ExitCode, Quiet));

        // The order of design 3.2: run_user, then the broker's own observation. It is the broker that decides.
        // The engine's report travels with it, so a failed or cancelled run is forced even if it left nothing.
        var observed = await _broker!.ObservedAsync(_prepared!.SessionId, result.Outcome, ct).ConfigureAwait(false);
        var gone = observed.VerifyGone.Passed;
        RunEnded?.Invoke(target, gone && !failed);
        SetStep(UninstallStep.CheckGone, gone ? StepState.Done : StepState.Warning,
            gone ? "Confirmed gone" : "Some parts remain");
        if (!gone)
            AddNotice(new UninstallNotice(UninstallNoticeKind.Warning, "The program is still installed.",
                "The broker's own check found parts of it. The leftover scan runs in the forced mode until you say so."));
        if (failed)
        {
            OnUninstallFailed(result.ExitCode, "The uninstaller did not finish successfully.");
            return;
        }
        if (result.Outcome == RunOutcome.SuccessReboot)
            AddNotice(RestartNotice());
        await FindLeftoversAsync(!gone, ct).ConfigureAwait(false);
    }

    private async Task CheckBrokerGoneAsync(RunResult result, CancellationToken ct)
    {
        var gone = result.VerifyGone.Passed;
        RunEnded?.Invoke(Target!, gone);
        SetStep(UninstallStep.CheckGone, gone ? StepState.Done : StepState.Warning,
            gone ? "Confirmed gone" : "Some parts remain");
        if (!gone)
            AddNotice(new UninstallNotice(UninstallNoticeKind.Warning, "The program is still installed.",
                "The broker's own check found parts of it. The leftover scan runs in the forced mode until you say so."));
        if (result.Outcome == RunOutcome.SuccessReboot || result.ExitCode == 3010)
            AddNotice(RestartNotice());
        await FindLeftoversAsync(!gone, ct).ConfigureAwait(false);
    }

    private async Task FindLeftoversAsync(bool forced, CancellationToken ct)
    {
        var target = Target!;
        if (_prepared is null) return;
        _force = forced;
        SetStep(UninstallStep.FindLeftovers, StepState.Active, "Looking for what it left");
        CurrentStep = UninstallStep.FindLeftovers;
        Raise();
        try
        {
            var scan = await _broker!.ScanAsync(_prepared.SessionId, forced,
                p => SetStep(UninstallStep.FindLeftovers, StepState.Active, p.Phase), ct).ConfigureAwait(false);
            SetStep(UninstallStep.FindLeftovers, StepState.Done, CountsText(scan));
            SetStep(UninstallStep.Ready, StepState.Done, "Ready for review");
            CurrentStep = UninstallStep.Ready;
            CompletedOutcome = new UninstallOutcome(target, _prepared.SessionId, scan.ScanId, scan.Mode, Quiet, RestorePoint);
            _retry = RetryStage.None;
            Raise();
            Completed?.Invoke(CompletedOutcome);
        }
        catch
        {
            _retry = RetryStage.Scan;
            throw;
        }
    }

    private void OnUninstallFailed(uint? exitCode, string message)
    {
        _retry = RetryStage.Run;
        var text = exitCode is { } code
            ? "The uninstaller ended with exit code " + code.ToString(System.Globalization.CultureInfo.InvariantCulture) + ". "
            : "";
        AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "The uninstaller failed.",
            text + "You can run the forced cleanup: Purge scans for what the program left and leaves the list for you to "
                   + "review, with nothing pre-selected. Or run the uninstaller again.", exitCode, CanRetry: true,
            CanForce: true));
    }

    private void FailWrongRoute(Route route)
    {
        _retry = RetryStage.None;
        FailRunningStep();
        var where = route == Route.Broker ? "the administrator part" : "the user's level";
        AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "The wrong part was asked to run this.",
            $"The program's uninstaller belongs to {where}. Nothing ran; Purge refuses a program of the other route."));
    }

    private static UninstallNotice RestartNotice() => new(UninstallNoticeKind.Info, "A restart is needed.",
        "The uninstaller asked Windows to finish after the next restart. Purge does not restart the PC.");

    private static string ExitDetail(uint? exitCode, bool quiet)
    {
        var code = exitCode is { } c ? c.ToString(System.Globalization.CultureInfo.InvariantCulture) : "unknown";
        return "Finished, exit code " + code + (quiet ? " · quiet mode" : "");
    }

    private static string CountsText(ScanResult scan)
    {
        var counts = scan.Counts;
        return $"{counts.Safe + counts.Likely + counts.Weak + counts.Blocked} leftovers ({(scan.Mode == ScanMode.Forced ? "forced" : "post")})"
               + $" · {counts.Preselected} pre-selected";
    }

    private static string ExitText(string message, uint? exitCode) =>
        exitCode is { } code ? message + $" (exit code {code.ToString(System.Globalization.CultureInfo.InvariantCulture)})" : message;

    private Task GuardAsync(Func<Task> operation, CancellationToken ct) => GuardAsync(async () =>
    {
        await operation().ConfigureAwait(false);
        return true;
    }, ct);

    private async Task GuardAsync(Func<Task<bool>> operation, CancellationToken ct)
    {
        if (_busy) return;
        _busy = true;
        Raise();
        try
        {
            await operation().ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            AddNotice(new UninstallNotice(UninstallNoticeKind.Info, "Uninstall stopped.",
                "Nothing more will run until you retry."));
        }
        catch (BrokerLinkException e)
        {
            FailRunningStep();
            AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "The administrator part ended.",
                e.Message + " Purge can start it again and record the program again.", CanStartOver: true));
            _retry = RetryStage.None;
        }
        catch (EngineLinkException e)
        {
            FailRunningStep();
            AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "Purge's engine ended.",
                e.Message + " Restart Purge; the program's own uninstaller may already have run.", CanStartOver: true));
            _retry = RetryStage.None;
        }
        catch (BrokerRpcException e)
        {
            FailRunningStep();
            AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "The administrator part refused the request.", e.Message,
                e.Details?.ExitCode, CanStartOver: true));
            _retry = RetryStage.None;
        }
        catch (EngineRpcException e)
        {
            FailRunningStep();
            AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "The engine refused the request.", e.Message,
                CanStartOver: true));
            _retry = RetryStage.None;
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            FailRunningStep();
            AddNotice(new UninstallNotice(UninstallNoticeKind.Error, "Something went wrong.", e.Message, CanStartOver: true));
            _retry = RetryStage.None;
        }
        finally
        {
            _busy = false;
            Raise();
        }
    }

    private void FailRunningStep()
    {
        if (_activeStep is { } step) SetStep(step, StepState.Failed, null);
    }

    private void Reset(UninstallTarget target)
    {
        Target = target;
        _prepared = null;
        _force = false;
        _retry = RetryStage.None;
        _answer = null;
        _activeStep = null;
        _notices.Clear();
        Command = null;
        QuietCommand = null;
        Signer = null;
        Running = [];
        QuietAvailable = false;
        Quiet = false;
        RouteText = null;
        LaunchState = null;
        CompletedOutcome = null;
        CurrentStep = UninstallStep.Record;
        ClearSteps();
        SetStep(UninstallStep.Record, StepState.Pending, null);
        Raise();
    }

    private void ClearSteps()
    {
        foreach (var step in Steps) _stepStates[step] = (StepState.Pending, null);
    }

    private void SetStep(UninstallStep step, StepState state, string? detail)
    {
        _stepStates[step] = (state, detail);
        if (state == StepState.Active) _activeStep = step;
        else if (_activeStep == step) _activeStep = null;
        if (state is StepState.Active or StepState.Done) CurrentStep = step;
    }

    private void AddNotice(UninstallNotice notice)
    {
        if (_notices.Any(n => n.Kind == notice.Kind && n.Title == notice.Title)) return;
        _notices.Add(notice);
    }

    private void ClearErrors() => _notices.RemoveAll(n => n.Kind == UninstallNoticeKind.Error);

    private void Raise() => Changed?.Invoke();

    private async Task DropBrokerAsync()
    {
        var broker = _broker;
        _broker = null;
        _detached = false;
        if (broker is not null) await broker.DisposeAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (!_detached) await DropBrokerAsync().ConfigureAwait(false);
    }
}
