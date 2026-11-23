using Purge.Client.Broker;
using Purge.Client.Pipeline;
using Purge.Client.Rpc;
using Purge.Client.Stdio;
using Xunit;

namespace Purge.Client.Tests;

/// <summary>
/// The Uninstall pipeline's view model (M3-UI-S2) against a scripted broker, medium engine and launcher: route
/// selection, a cancelled UAC, wrong_route on both sides, a failed uninstaller with the forced offer, a still-installed
/// program, a restart, and a link that dies mid-run. The real broker, the real UAC and a real uninstaller are VM items.
/// </summary>
public sealed class UninstallPageTests
{
    private const string Program = "HKLM|64|App_is1";
    private static readonly UninstallTarget Target = new(Program, "App");

    // ---- route selection ------------------------------------------------------------------------------------

    [Fact]
    public async Task A_broker_route_shows_the_brokers_command_and_runs_with_the_same_quiet_choice()
    {
        var broker = new ScriptedBroker
        {
            PreparedProgram = PreparedFor(Route.Broker, @"""C:\Program Files\App\unins000.exe"" /S"),
        };
        var medium = new ScriptedMedium();
        var controller = Controller(Started(broker), medium);
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        var confirmation = await asked.NextAsync();

        Assert.Equal(Route.Broker, broker.PreparedProgram.Route);
        Assert.Equal(@"""C:\Program Files\App\unins000.exe"" /S", confirmation.Command);
        Assert.Equal("App Signer", confirmation.Signer);
        Assert.True(confirmation.QuietAvailable);
        Assert.Contains(confirmation.Steps, s => s.Contains("as administrator", StringComparison.Ordinal));
        Assert.Equal(0, medium.RouteCalls);
        Assert.Equal(StepState.Done, controller.StateOf(UninstallStep.Record));
        Assert.Equal(StepState.Pending, controller.StateOf(UninstallStep.Run));
        Assert.Equal(StepState.Pending, controller.StateOf(UninstallStep.Ready));

        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, broker.RunCalls);
        Assert.True(broker.RunQuiet);
        Assert.Equal(@"""C:\Program Files\App\unins000.exe"" /S", broker.CommandFor(broker.RunQuiet));
        Assert.Equal(0, medium.RunCalls);
        Assert.NotNull(controller.CompletedOutcome);
        Assert.Equal(ScanMode.Post, controller.CompletedOutcome!.Mode);
        Assert.Equal(RestorePoint.HighRisk, controller.CompletedOutcome.RestorePoint);
        Assert.Equal(StepState.Done, controller.StateOf(UninstallStep.CheckGone));
        Assert.Equal(StepState.Done, controller.StateOf(UninstallStep.FindLeftovers));
        Assert.Equal(StepState.Done, controller.StateOf(UninstallStep.Ready));
    }

    [Fact]
    public async Task A_medium_route_shows_the_engines_command_runs_it_and_then_the_broker_observes()
    {
        var broker = new ScriptedBroker
        {
            PreparedProgram = PreparedFor(Route.Medium, @"""C:\Program Files\App\unins000.exe"" /S"),
        };
        var medium = new ScriptedMedium
        {
            Route = RouteOf(Route.Medium, @"""C:\Users\u\AppData\Local\App\unins000.exe"" /interactive",
                @"""C:\Users\u\AppData\Local\App\unins000.exe"" /S"),
        };
        var controller = Controller(Started(broker), medium);
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        var confirmation = await asked.NextAsync();

        // The command shown is the medium engine's, because it is the process that runs it.
        Assert.Equal(@"""C:\Users\u\AppData\Local\App\unins000.exe"" /S", confirmation.Command);
        Assert.Equal(1, medium.RouteCalls);
        Assert.Contains(confirmation.Steps, s => s.Contains("at your level", StringComparison.Ordinal));

        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.Always));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, medium.RunCalls);
        Assert.True(medium.RunQuiet);
        Assert.Equal(medium.CommandFor(true), confirmation.Command);
        Assert.Equal(0, broker.RunCalls);
        Assert.Equal(1, broker.ObservedCalls);
        Assert.Equal(RunOutcome.Success, broker.ObservedOutcome);
        Assert.True(broker.ObservedBeforeScan, "the order is prepare, run_user, observed");
        Assert.Equal(RestorePoint.Always, controller.CompletedOutcome!.RestorePoint);
    }

    [Fact]
    public async Task A_quietless_program_offers_only_its_interactive_command()
    {
        var broker = new ScriptedBroker { PreparedProgram = PreparedFor(Route.Broker, quiet: null) };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        var confirmation = await asked.NextAsync();
        Assert.False(confirmation.QuietAvailable);
        Assert.False(confirmation.Quiet);

        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.False(broker.RunQuiet, "a program with no quiet command runs interactively");
    }

    // ---- a cancelled UAC ------------------------------------------------------------------------------------

    [Fact]
    public async Task A_cancelled_uac_changes_nothing_and_shows_the_cancelled_bar()
    {
        var controller = Controller(new UninstallLaunch(UninstallLaunchState.Cancelled, null,
            "You cancelled the Windows prompt. Nothing was changed."), new ScriptedMedium());
        bool? declined = null;
        controller.AdminPromptCancelled += d => declined = d;

        await controller.BeginAsync(Target).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(declined); // raised, and it was the Windows prompt
        Assert.Equal(UninstallLaunchState.Cancelled, controller.LaunchState);
        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Info, notice.Kind);
        // "Not now" at the explanation ends here too, so the words do not claim a cancelled Windows prompt.
        Assert.Equal("Administrator permission was not given.", notice.Title);
        Assert.Null(controller.Command);
        Assert.Null(controller.CompletedOutcome);
    }

    [Fact]
    public async Task Not_now_at_the_explanation_reaches_the_bar_as_declined()
    {
        var controller = Controller(new UninstallLaunch(UninstallLaunchState.Cancelled, null, "", null,
            DeclinedExplanation: true), new ScriptedMedium());
        bool? declined = null;
        controller.AdminPromptCancelled += d => declined = d;

        await controller.BeginAsync(Target).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(declined);
        Assert.Equal("Administrator permission was not given.", Assert.Single(controller.Notices).Title);
    }

    [Fact]
    public async Task A_standard_user_is_told_an_administrator_account_is_needed()
    {
        var controller = Controller(new UninstallLaunch(UninstallLaunchState.NotAdministrator, null,
            BrokerLauncher.StandardUserMessage), new ScriptedMedium());

        await controller.BeginAsync(Target).WaitAsync(TimeSpan.FromSeconds(5));

        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Error, notice.Kind);
        Assert.Contains("administrator account", notice.Message, StringComparison.OrdinalIgnoreCase);
        // The title and the launcher's sentence are read together; the title does not say it a second time.
        Assert.DoesNotContain("administrator account", notice.Title, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("remove programs", notice.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(notice.CanStartOver);
        Assert.Equal(StepState.Failed, controller.StateOf(UninstallStep.Record));
    }

    [Fact]
    public async Task A_broker_that_exits_before_its_pipe_shows_its_exit_code()
    {
        var controller = Controller(new UninstallLaunch(UninstallLaunchState.CannotStart, null,
            "The administrator part could not start", 5), new ScriptedMedium());

        await controller.BeginAsync(Target).WaitAsync(TimeSpan.FromSeconds(5));

        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Error, notice.Kind);
        Assert.Equal(5U, notice.ExitCode);
        Assert.True(notice.CanStartOver);
    }

    // ---- wrong route ----------------------------------------------------------------------------------------

    [Fact]
    public async Task A_medium_prepare_whose_engine_says_broker_is_a_wrong_route_refusal()
    {
        var broker = new ScriptedBroker { PreparedProgram = PreparedFor(Route.Medium) };
        var medium = new ScriptedMedium { Route = RouteOf(Route.Broker, @"""C:\Program Files\App\unins000.exe""") };
        var controller = Controller(Started(broker), medium);
        var asked = new ConfirmationQueue(controller);

        await controller.BeginAsync(Target).WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(asked.Any);
        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Error, notice.Kind);
        Assert.Contains("wrong part", notice.Title, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(0, medium.RunCalls);
        Assert.Equal(0, broker.RunCalls);
        Assert.Null(controller.CompletedOutcome);
        Assert.Equal(StepState.Failed, controller.StateOf(UninstallStep.Record));
        Assert.Equal(StepState.Pending, controller.StateOf(UninstallStep.Run));
    }

    [Fact]
    public async Task A_broker_run_refused_with_wrong_route_is_shown_as_that()
    {
        var broker = new ScriptedBroker
        {
            PreparedProgram = PreparedFor(Route.Broker),
            RunThrows = new BrokerRpcException(-32000, "wrong_route", "wrong_route",
                new ErrorData { Kind = "wrong_route", Route = Route.Medium }),
        };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Error, notice.Kind);
        Assert.Contains("wrong part", notice.Title, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(StepState.Failed, controller.StateOf(UninstallStep.Run));
        Assert.Null(controller.CompletedOutcome);
    }

    // ---- the broker's own dialog (review M3-R2 M1) ------------------------------------------------------------

    [Fact]
    public async Task While_the_brokers_dialog_is_open_the_run_step_waits_and_says_nothing_has_run()
    {
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var broker = new ScriptedBroker { PreparedProgram = PreparedFor(Route.Broker), RunGate = gate };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.Always));
        await WaitUntilAsync(() => broker.RunCalls == 1);

        Assert.Equal(StepState.Active, controller.StateOf(UninstallStep.Run));
        Assert.Contains("Waiting for the Purge security prompt", controller.DetailOf(UninstallStep.Run),
            StringComparison.Ordinal);
        Assert.Contains("Nothing has run yet", controller.DetailOf(UninstallStep.Run), StringComparison.Ordinal);
        Assert.Equal(RestorePoint.Always, broker.RunRestorePoint);

        broker.RaiseConsentShown("A1B2-C3D4");
        Assert.Contains("A1B2-C3D4", controller.DetailOf(UninstallStep.Run), StringComparison.Ordinal);
        Assert.Contains("Nothing has run yet", controller.DetailOf(UninstallStep.Run), StringComparison.Ordinal);
        Assert.Null(controller.CompletedOutcome);

        gate.SetResult();
        await begin.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(StepState.Done, controller.StateOf(UninstallStep.Run));
        Assert.NotNull(controller.CompletedOutcome);
    }

    [Fact]
    public async Task A_declined_broker_dialog_runs_nothing_and_Retry_asks_again()
    {
        var broker = new ScriptedBroker
        {
            PreparedProgram = PreparedFor(Route.Broker),
            FirstRunThrows = new BrokerRpcException(-32000, "consent_declined", "consent_declined",
                new ErrorData { Kind = "consent_declined" }),
        };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Info, notice.Kind);
        Assert.Contains("declined", notice.Title, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Nothing was run", notice.Message, StringComparison.Ordinal);
        Assert.True(notice.CanRetry);
        Assert.False(notice.CanForce, "nothing ran, so there is nothing to force");
        Assert.Equal(StepState.Warning, controller.StateOf(UninstallStep.Run));
        Assert.Equal(0, broker.ObservedCalls);
        Assert.Equal(0, broker.ScanCalls);
        Assert.Null(controller.CompletedOutcome);

        await controller.RetryAsync().WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal(2, broker.RunCalls);
        Assert.NotNull(controller.CompletedOutcome);
    }

    // ---- a failed uninstaller, with forced offered ----------------------------------------------------------

    [Fact]
    public async Task A_failed_broker_uninstaller_offers_the_forced_cleanup_and_scans_forced()
    {
        var broker = new ScriptedBroker
        {
            PreparedProgram = PreparedFor(Route.Broker),
            RunThrows = new BrokerRpcException(-32000, "uninstall_failed", "uninstall_failed",
                new ErrorData { Kind = "uninstall_failed", ExitCode = 1603, ForcedOffered = true }),
        };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);
        var completed = new TaskCompletionSource<UninstallOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        controller.Completed += outcome => completed.TrySetResult(outcome);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Error, notice.Kind);
        Assert.Equal(1603U, notice.ExitCode);
        Assert.True(notice.CanForce, "forced_offered from error.data");
        Assert.True(notice.CanRetry);
        Assert.Equal(StepState.Failed, controller.StateOf(UninstallStep.Run));
        Assert.Equal(0, broker.ScanCalls);

        await controller.ForceAsync().WaitAsync(TimeSpan.FromSeconds(5));
        var outcome = await completed.Task.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(broker.ScanForced);
        Assert.Equal(1, broker.ScanCalls);
        Assert.Equal(ScanMode.Forced, outcome.Mode);
        Assert.DoesNotContain(controller.Notices, n => n.Kind == UninstallNoticeKind.Error);
    }

    [Fact]
    public async Task A_failed_medium_uninstaller_observes_then_offers_the_forced_cleanup()
    {
        var broker = new ScriptedBroker { PreparedProgram = PreparedFor(Route.Medium) };
        var medium = new ScriptedMedium
        {
            Route = RouteOf(Route.Medium),
            Run = new RunUserResult { ExitCode = 1603, Outcome = RunOutcome.Failed },
        };
        var controller = Controller(Started(broker), medium);
        var asked = new ConfirmationQueue(controller);
        var completed = new TaskCompletionSource<UninstallOutcome>(TaskCreationOptions.RunContinuationsAsynchronously);
        controller.Completed += outcome => completed.TrySetResult(outcome);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(1, broker.ObservedCalls);
        Assert.Equal(RunOutcome.Failed, broker.ObservedOutcome);
        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Error, notice.Kind);
        Assert.Equal(1603U, notice.ExitCode);
        Assert.True(notice.CanForce);

        await controller.ForceAsync().WaitAsync(TimeSpan.FromSeconds(5));
        var outcome = await completed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.True(broker.ScanForced);
        Assert.Equal(ScanMode.Forced, outcome.Mode);
        Assert.Equal(1, broker.ObservedCalls);
    }

    // ---- a stage that runs again clears the scan from before ---------------------------------------------------

    [Fact]
    public async Task Check_again_after_a_completed_scan_leaves_no_outcome_until_the_new_scan_is_in()
    {
        // The Uninstall page may hold the completed scan for the Leftovers page; while the pipeline runs again it must
        // not hand that scan over with the broker this run is using (Fable review of ui-broker-followups, must-fix 2).
        var broker = new ScriptedBroker { PreparedProgram = PreparedFor(Route.Broker) };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));
        var first = controller.CompletedOutcome;
        Assert.NotNull(first);

        var recheck = controller.RecheckAsync();
        await asked.NextAsync();

        Assert.True(controller.IsBusy);
        Assert.Null(controller.CompletedOutcome);
        Assert.Same(broker, controller.Broker);

        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await recheck.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.NotNull(controller.CompletedOutcome);
        Assert.NotSame(first, controller.CompletedOutcome);
        Assert.Equal(2, broker.ScanCalls);
    }

    [Fact]
    public async Task A_forced_cleanup_after_a_completed_scan_clears_the_old_outcome_before_it_scans()
    {
        var broker = new ScriptedBroker { PreparedProgram = PreparedFor(Route.Broker) };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));
        var first = controller.CompletedOutcome;
        Assert.NotNull(first);

        var clearedWhileBusy = false;
        controller.Changed += () =>
        {
            if (controller.IsBusy && controller.CompletedOutcome is null) clearedWhileBusy = true;
        };
        await controller.ForceAsync().WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(clearedWhileBusy, "the scan from before stayed while the forced scan ran");
        Assert.NotSame(first, controller.CompletedOutcome);
        Assert.True(controller.CompletedOutcome!.Forced);
    }

    // ---- still installed and restart -------------------------------------------------------------------------

    [Fact]
    public async Task A_still_installed_program_scans_forced_and_says_so()
    {
        var broker = new ScriptedBroker
        {
            PreparedProgram = PreparedFor(Route.Broker),
            Run = new RunResult
            {
                ExitCode = 0,
                Outcome = RunOutcome.Success,
                VerifyGone = new VerifyGone { ArpGone = true, MainExesGone = false, MsiUnknownAllCtx = true, Passed = false },
            },
        };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(broker.ScanForced);
        Assert.Equal(StepState.Warning, controller.StateOf(UninstallStep.CheckGone));
        Assert.Contains(controller.Notices, n => n.Kind == UninstallNoticeKind.Warning
                                                 && n.Title.Contains("still installed", StringComparison.OrdinalIgnoreCase));
        Assert.True(controller.CompletedOutcome!.Forced);
    }

    [Fact]
    public async Task A_restart_request_is_text_only()
    {
        var broker = new ScriptedBroker
        {
            PreparedProgram = PreparedFor(Route.Broker),
            Run = new RunResult
            {
                ExitCode = 3010,
                Outcome = RunOutcome.SuccessReboot,
                VerifyGone = new VerifyGone { Passed = true, ArpGone = true, MainExesGone = true, MsiUnknownAllCtx = true },
            },
        };
        var controller = Controller(Started(broker), new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Contains(controller.Notices, n => n.Kind == UninstallNoticeKind.Info
                                                 && n.Title.Contains("restart", StringComparison.OrdinalIgnoreCase));
        Assert.NotNull(controller.CompletedOutcome);
    }

    // ---- links that die mid-run ------------------------------------------------------------------------------

    [Fact]
    public async Task A_broker_that_dies_mid_run_keeps_the_page_and_offers_a_start_over()
    {
        var broker = new ScriptedBroker
        {
            PreparedProgram = PreparedFor(Route.Broker),
            RunThrows = new BrokerLinkException("The administrator part ended."),
        };
        var launches = 0;
        var controller = Controller(_ =>
        {
            launches++;
            return Task.FromResult(Started(broker));
        }, new ScriptedMedium());
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Error, notice.Kind);
        Assert.Contains("administrator part ended", notice.Title, StringComparison.OrdinalIgnoreCase);
        Assert.True(notice.CanStartOver);
        Assert.Equal(StepState.Failed, controller.StateOf(UninstallStep.Run));

        // Start over closes the dead link and starts a fresh broker: the UAC prompt appears again.
        var restart = controller.StartOverAsync();
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(false, Quiet: true, RestorePoint.HighRisk));
        await restart.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(2, launches);
        Assert.True(broker.Disposed);
        Assert.Contains(controller.Notices, n => n.Kind == UninstallNoticeKind.Info
                                                 && n.Title.Contains("cancelled", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task An_engine_that_dies_mid_run_asks_for_a_restart_of_purge()
    {
        var broker = new ScriptedBroker { PreparedProgram = PreparedFor(Route.Medium) };
        var medium = new ScriptedMedium
        {
            Route = RouteOf(Route.Medium),
            RunThrows = new EngineLinkException("The engine ended (exit code 3)."),
        };
        var controller = Controller(Started(broker), medium);
        var asked = new ConfirmationQueue(controller);

        var begin = controller.BeginAsync(Target);
        await asked.NextAsync();
        await controller.AnswerAsync(new UninstallAnswer(true, Quiet: true, RestorePoint.HighRisk));
        await begin.WaitAsync(TimeSpan.FromSeconds(5));

        var notice = Assert.Single(controller.Notices);
        Assert.Equal(UninstallNoticeKind.Error, notice.Kind);
        Assert.Contains("engine ended", notice.Title, StringComparison.OrdinalIgnoreCase);
        Assert.True(notice.CanStartOver);
        Assert.Equal(0, broker.ObservedCalls);
    }

    // ---- helpers ---------------------------------------------------------------------------------------------

    private static UninstallController Controller(UninstallLaunch launch, IMediumUninstall medium) =>
        new(_ => Task.FromResult(launch), medium);

    private static UninstallController Controller(Func<CancellationToken, Task<UninstallLaunch>> launch,
        IMediumUninstall medium) => new(launch, medium);

    private static UninstallLaunch Started(IUninstallBroker broker) =>
        new(UninstallLaunchState.Started, broker, "");

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, "the condition did not come true");
            await Task.Delay(10);
        }
    }

    private static Prepared PreparedFor(Route route, string? quiet = @"""C:\Program Files\App\unins000.exe"" /S")
    {
        var command = @"""C:\Program Files\App\unins000.exe""";
        return new Prepared
        {
            ProgramId = Program,
            SessionId = "u-1122334455667788",
            Route = route,
            Command = command,
            QuietCommand = quiet,
            Signer = "App Signer",
            Running = [],
            FingerprintSummary = new FingerprintSummary { Roots = 1, Files = 2, Registry = 3, Objects = 0 },
            Warnings = [],
            CoProducts = [],
        };
    }

    private static RouteInfo RouteOf(Route route, string command = @"""C:\Program Files\App\unins000.exe""",
        string? quiet = @"""C:\Program Files\App\unins000.exe"" /S") => new()
    {
        Route = route,
        Command = command,
        QuietCommand = quiet,
        Signer = "App Signer",
        Running = [],
    };

    private sealed class ConfirmationQueue
    {
        private readonly Queue<UninstallConfirmation> _queue = new();
        private TaskCompletionSource<UninstallConfirmation>? _next;

        public ConfirmationQueue(UninstallController controller)
        {
            controller.ConfirmationRequested += confirmation =>
            {
                lock (_queue)
                {
                    if (_next is not null)
                    {
                        var waiting = _next;
                        _next = null;
                        waiting.TrySetResult(confirmation);
                    }
                    else _queue.Enqueue(confirmation);
                }
            };
        }

        public bool Any
        {
            get { lock (_queue) return _queue.Count > 0; }
        }

        public Task<UninstallConfirmation> NextAsync()
        {
            lock (_queue)
            {
                if (_queue.Count > 0) return Task.FromResult(_queue.Dequeue());
                _next = new TaskCompletionSource<UninstallConfirmation>(TaskCreationOptions.RunContinuationsAsynchronously);
                return _next.Task.WaitAsync(TimeSpan.FromSeconds(5));
            }
        }
    }

    private sealed class ScriptedBroker : IUninstallBroker
    {
        public Prepared PreparedProgram { get; init; } = PreparedFor(Route.Broker);
        public RunResult Run { get; init; } = new()
        {
            ExitCode = 0,
            Outcome = RunOutcome.Success,
            VerifyGone = new VerifyGone { ArpGone = true, MainExesGone = true, MsiUnknownAllCtx = true, Passed = true },
        };
        public Exception? RunThrows { get; init; }

        public int PrepareCalls { get; private set; }
        public int RunCalls { get; private set; }
        public bool RunQuiet { get; private set; }
        public int ObservedCalls { get; private set; }
        public RunOutcome? ObservedOutcome { get; private set; }
        public int ScanCalls { get; private set; }
        public bool ScanForced { get; private set; }
        public bool ObservedBeforeScan { get; private set; }
        public bool Disposed { get; private set; }

        public Task<PrepareResult> PrepareAsync(IReadOnlyList<string> programIds, Action<Progress>? progress,
            CancellationToken ct)
        {
            PrepareCalls++;
            return Task.FromResult(new PrepareResult { Programs = [PreparedProgram] });
        }

        public event Action<ConsentShown>? ConsentShown;

        /// <summary>When set, <c>uninstall.run</c> waits for it: the broker's dialog is open.</summary>
        public TaskCompletionSource? RunGate { get; init; }

        /// <summary>Thrown by the first run only; the next one succeeds.</summary>
        public Exception? FirstRunThrows { get; init; }

        public RestorePoint? RunRestorePoint { get; private set; }

        public void RaiseConsentShown(string code) => ConsentShown?.Invoke(new ConsentShown { Code = code });

        public async Task<RunResult> RunAsync(string sessionId, bool quiet, RestorePoint restorePoint,
            Action<Progress>? progress, CancellationToken ct)
        {
            RunCalls++;
            RunQuiet = quiet;
            RunRestorePoint = restorePoint;
            if (RunGate is { } gate) await gate.Task.WaitAsync(ct);
            if (RunCalls == 1 && FirstRunThrows is { } first) throw first;
            if (RunThrows is { } error) throw error;
            return Run;
        }

        public Task<ObservedResult> ObservedAsync(string sessionId, RunOutcome? outcome, CancellationToken ct)
        {
            ObservedCalls++;
            ObservedOutcome = outcome;
            return Task.FromResult(new ObservedResult
            {
                VerifyGone = new VerifyGone { ArpGone = true, MainExesGone = true, MsiUnknownAllCtx = true, Passed = true },
            });
        }

        public Task<ScanResult> ScanAsync(string sessionId, bool forced, Action<Progress>? progress, CancellationToken ct)
        {
            ScanCalls++;
            ScanForced = forced;
            ObservedBeforeScan = ObservedCalls > 0;
            return Task.FromResult(new ScanResult
            {
                ScanId = "s-0123456789abcdef",
                Mode = forced ? ScanMode.Forced : ScanMode.Post,
                BaselineTrust = BaselineTrust.Exact,
                Counts = new BandCounts { Safe = 3, Likely = 1, Preselected = 3 },
                Warnings = [],
            });
        }

        public string CommandFor(bool quiet) => quiet ? PreparedProgram.QuietCommand ?? PreparedProgram.Command : PreparedProgram.Command;

        public ValueTask DisposeAsync()
        {
            Disposed = true;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class ScriptedMedium : IMediumUninstall
    {
        public RouteInfo Route { get; init; } = UninstallPageTests.RouteOf(Rpc.Route.Medium);
        public RunUserResult Run { get; init; } = new() { ExitCode = 0, Outcome = RunOutcome.Success };
        public Exception? RunThrows { get; init; }
        public int RouteCalls { get; private set; }
        public int RunCalls { get; private set; }
        public bool RunQuiet { get; private set; }

        public Task<RouteInfo> RouteAsync(string programId, CancellationToken ct)
        {
            RouteCalls++;
            return Task.FromResult(Route);
        }

        public Task<RunUserResult> RunUserAsync(string programId, bool quiet, Action<Progress>? progress,
            CancellationToken ct)
        {
            RunCalls++;
            RunQuiet = quiet;
            if (RunThrows is { } error) return Task.FromException<RunUserResult>(error);
            return Task.FromResult(Run);
        }

        public string CommandFor(bool quiet) => quiet ? Route.QuietCommand ?? Route.Command : Route.Command;
    }
}
