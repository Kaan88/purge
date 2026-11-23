using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Purge.App.Shell;
using Purge.Client.Broker;
using Purge.Client.Pipeline;
using Purge.Client.Rpc;
using Windows.UI;

namespace Purge.App.Views;

/// <summary>
/// S2: the Uninstall pipeline page. It starts the elevated broker on the Uninstall click (never at app start), shows
/// the confirm dialog with the exact command and signer, walks the five-step stepper, and hands the scan to the
/// leftovers page. All state and every error live in <see cref="UninstallController"/>; this file only draws it.
/// </summary>
public sealed partial class UninstallView : UserControl
{
    private static readonly Brush DoneBrush = new SolidColorBrush(Color.FromArgb(255, 0x2E, 0x9E, 0x44));
    private static readonly Brush WarningBrush = new SolidColorBrush(Color.FromArgb(255, 0xC7, 0x7B, 0x00));
    private static readonly Brush ErrorBrush = new SolidColorBrush(Color.FromArgb(255, 0xD1, 0x34, 0x38));
    private static readonly Brush PendingBrush = new SolidColorBrush(Color.FromArgb(255, 0x8A, 0x8A, 0x8A));

    private static readonly (UninstallStep Step, string Title)[] StepTitles =
    [
        (UninstallStep.Record, "Record what it registered"),
        (UninstallStep.Run, "Run its own uninstaller"),
        (UninstallStep.CheckGone, "Check that it is gone"),
        (UninstallStep.FindLeftovers, "Find its leftovers"),
        (UninstallStep.Ready, "Ready for review"),
    ];

    private readonly UninstallController _controller;
    private readonly UninstallQueue _queue = new();
    private readonly Dictionary<UninstallStep, StepRow> _rows = [];
    private bool _rendering;
    private bool _wasBusy;

    // A scan that could not go to the Leftovers page because that page was applying another change, or because that
    // page is on screen with the change's outcome (it must not be replaced unread). The controller keeps its broker
    // meanwhile; the hand-off is tried again when that change ends, when the user leaves the Leftovers page, and by
    // "Show leftovers".
    private UninstallOutcome? _heldOutcome;

    // The program whose held scan a new run closed, for a bar that says so; null when there is none. _droppedRerun:
    // the same program's uninstall ran again (Check again, Retry, Run forced cleanup, Start over), not a new one.
    private string? _droppedHeld;
    private bool _droppedRerun;

    // A held scan handed to the Leftovers page while the user went to another page (they are not taken there): the
    // bar says where it went. Null when there is none, or once that scan is no longer the pipeline's.
    private UninstallOutcome? _handedQuietly;

    /// <summary>The tooltip of an action that waits for a removed program's leftovers check (one broker at a time).</summary>
    private const string CheckRunningHint = "A leftovers check is running on the Programs page. Try again when it has finished.";

    private sealed class StepRow(TextBlock glyph, TextBlock title, TextBlock detail)
    {
        public TextBlock Glyph { get; } = glyph;
        public TextBlock Title { get; } = title;
        public TextBlock Detail { get; } = detail;
    }

    public UninstallView()
    {
        InitializeComponent();
        _controller = new UninstallController(LaunchAsync, new EngineMediumUninstall(Program.Engine));
        _controller.Changed += () => DispatcherQueue.TryEnqueue(Render);
        _controller.ConfirmationRequested += OnConfirmationRequested;
        _controller.Completed += OnCompleted;
        _controller.RunEnded += (target, removed) => DispatcherQueue.TryEnqueue(
            () => _ = MainWindow.Instance.Programs.OnUninstallRunEndedAsync(target.ProgramId, removed));
        // A cancelled or declined admin prompt is said by this page's own bar (the controller's notice, with "Try
        // again"), not by the window's bar as well.

        BuildStepper();
        BuildChoices();
        Built = this;
        Render();
    }

    /// <summary>True while the pipeline runs a step (the Programs page's removed-program check waits meanwhile).</summary>
    public bool IsBusy => _controller.IsBusy;

    /// <summary>A removed program's leftovers check started or ended: the actions that start a broker follow it.</summary>
    public void OnCheckRunningChanged() => DispatcherQueue.TryEnqueue(Render);

    /// <summary>
    /// The Leftovers page started or finished a change. A held scan goes there once it has finished, unless that page
    /// is on screen: then its outcome (a result, an interrupted change, refusal lines) is being read, and the scan
    /// waits until the user leaves the page (<see cref="OnLeftoversLeft"/>) or asks for it.
    /// </summary>
    public void OnLeftoversChangingChanged() => DispatcherQueue.TryEnqueue(() => TryHandOffHeld(navigate: true));

    /// <summary>
    /// The user left the Leftovers page: a held scan goes there now, without taking the user back (they chose where
    /// to go); the bar on this page says where it went.
    /// </summary>
    public void OnLeftoversLeft() => DispatcherQueue.TryEnqueue(() => TryHandOffHeld(navigate: false));

    /// <summary>"Show the scan" on the Leftovers page: the held scan replaces what that page shows.</summary>
    public void ShowHeld() => DispatcherQueue.TryEnqueue(ShowHeldNow);

    /// <summary>The program whose scan waits for the Leftovers page, for that page's line; null when none waits.</summary>
    public string? HeldProgram => _heldOutcome is { } held ? NameOf(held) : null;

    private static string NameOf(UninstallOutcome outcome) =>
        outcome.Target.ProgramName is { Length: > 0 } name ? name : "the last program";

    private static bool LeftoversOnScreen => MainWindow.Instance.CurrentPage == "leftovers";

    private void TryHandOffHeld(bool navigate)
    {
        // Never while the pipeline runs a step: it may be using the broker the held scan would take with it.
        if (_heldOutcome is { } held && !_controller.IsBusy && !LeftoversNavigator.IsChanging && !LeftoversOnScreen)
            HandOff(held, navigate);
        else
            Render();
    }

    private void ShowHeldNow()
    {
        if (_heldOutcome is { } held && !_controller.IsBusy) HandOff(held);
        else Render();
    }

    /// <summary>Holds <paramref name="outcome"/> (or nothing) and tells the Leftovers page, which shows a line for it.</summary>
    private void SetHeld(UninstallOutcome? outcome)
    {
        if (ReferenceEquals(outcome, _heldOutcome)) return;
        _heldOutcome = outcome;
        MainWindow.Instance.OnHeldScanChanged();
    }

    /// <summary>True while a removed program's leftovers check runs: Retry, Force, Start over and the choices wait.</summary>
    private static bool CheckRunning => MainWindow.Instance.CheckRunning;

    /// <summary>Starts the pipeline for a program chosen on the Programs page.</summary>
    public void Begin(UninstallTarget target) => Begin([target]);

    /// <summary>
    /// Starts the pipeline for the programs ticked on the Programs page, one after another: the first now, each next
    /// one when the user asks for it on this page ("Uninstall next" or "Skip"). Ignored while a step runs.
    /// </summary>
    public void Begin(IReadOnlyList<UninstallTarget> targets)
    {
        if (_controller.IsBusy) return;
        if (_queue.Start(targets) is not { } first) return;
        StartQueued(first);
    }

    /// <summary>The page once it is built (the window builds it on first use), for the Leftovers page's queue line.</summary>
    public static UninstallView? Built { get; private set; }

    /// <summary>The program the queue names after the current one, for the Leftovers page's line; null when none.</summary>
    public string? QueuedNext => _queue.Next is { } next && !_controller.IsBusy
        ? $"{(next.ProgramName.Length > 0 ? next.ProgramName : "The next program")} ({_queue.Position + 1} of {_queue.Count})"
        : null;

    private void StartQueued(UninstallTarget target)
    {
        ProgramTile.Background = ProgramRow.TileFor(target.ProgramName);
        _ = _controller.BeginAsync(target);
        MainWindow.Instance.OnHeldScanChanged();
        Render();
    }

    private void OnUninstallNext(object sender, RoutedEventArgs e)
    {
        if (!CanStartNext(out _)) return;
        if (_queue.Advance() is { } next) StartQueued(next);
    }

    private void OnSkipNext(object sender, RoutedEventArgs e)
    {
        _queue.SkipNext();
        MainWindow.Instance.OnHeldScanChanged();
        Render();
    }

    /// <summary>The next queued program may start: no step runs, and no other broker user or held scan is in the way.</summary>
    private bool CanStartNext(out string? why)
    {
        why = _controller.IsBusy ? "Waits until this program's step has finished."
            : CheckRunning ? CheckRunningHint
            : LeftoversNavigator.IsChanging ? "Waits until the Leftovers page has finished its change."
            : _heldOutcome is not null ? "Waits until this program's scan has gone to the Leftovers page."
            : null;
        return why is null;
    }

    private void RenderQueue()
    {
        if (_queue.Next is not { } next || _controller.IsBusy)
        {
            NextCard.Visibility = Visibility.Collapsed;
            return;
        }
        var name = next.ProgramName.Length > 0 ? next.ProgramName : "the next program";
        NextCard.Visibility = Visibility.Visible;
        NextText.Text = $"Next: {name} ({_queue.Position + 1} of {_queue.Count}).";
        NextDetail.Text = "It gets its own confirmation, prompts and leftover scan. Review this program's leftovers first "
                          + "if you like; the next one starts only when you choose.";
        NextButton.Content = "Uninstall " + name;
        AutomationProperties.SetName(NextButton, "Uninstall " + name);
        var can = CanStartNext(out var why);
        NextButton.IsEnabled = can;
        ToolTipService.SetToolTip(NextButton, why);
        AutomationProperties.SetName(SkipButton, "Skip " + name);
    }

    private async Task<UninstallLaunch> LaunchAsync(CancellationToken ct)
    {
        try
        {
            if (!await MainWindow.Instance.ConfirmFirstElevationAsync())
                return new UninstallLaunch(UninstallLaunchState.Cancelled, null, "", null, DeclinedExplanation: true);
            var result = await BrokerLauncher.LaunchAsync(BrokerLauncher.PathBesideApp(), ct);
            var exitCode = result.ExitCode is { } code ? (uint)code : (uint?)null;
            return result.Status switch
            {
                BrokerLaunchStatus.Started when result.Session is { } session =>
                    new UninstallLaunch(UninstallLaunchState.Started, new BrokerUninstallClient(session), "", null),
                BrokerLaunchStatus.Cancelled => new UninstallLaunch(UninstallLaunchState.Cancelled, null, result.Message, null),
                BrokerLaunchStatus.NotAdministrator =>
                    new UninstallLaunch(UninstallLaunchState.NotAdministrator, null, result.Message, null),
                BrokerLaunchStatus.TimedOut or BrokerLaunchStatus.ServerCheckFailed =>
                    new UninstallLaunch(UninstallLaunchState.Failed, null, result.Message, null),
                _ => new UninstallLaunch(UninstallLaunchState.CannotStart, null, result.Message, exitCode),
            };
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return new UninstallLaunch(UninstallLaunchState.CannotStart, null, e.Message, null);
        }
    }

    private void BuildStepper()
    {
        foreach (var (step, title) in StepTitles)
        {
            var glyph = new TextBlock
            {
                Text = "\u25CB",
                FontSize = 14,
                Width = 18,
                VerticalAlignment = VerticalAlignment.Top,
                Foreground = PendingBrush,
            };
            var titleText = new TextBlock { Text = title, FontSize = 13, FontWeight = FontWeights.SemiBold };
            var detail = new TextBlock
            {
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Foreground = PendingBrush,
                Visibility = Visibility.Collapsed,
            };
            var body = new StackPanel { Spacing = 1 };
            body.Children.Add(titleText);
            body.Children.Add(detail);
            var row = new Grid { ColumnSpacing = 10 };
            row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            row.ColumnDefinitions.Add(new ColumnDefinition());
            row.Children.Add(glyph);
            Grid.SetColumn(body, 1);
            row.Children.Add(body);
            StepperHost.Children.Add(row);
            _rows[step] = new StepRow(glyph, titleText, detail);
        }
    }

    private void BuildChoices()
    {
        RestorePointBox.Items.Add(new ComboBoxItem { Content = "Off" });
        RestorePointBox.Items.Add(new ComboBoxItem { Content = "High-risk changes only (default)" });
        RestorePointBox.Items.Add(new ComboBoxItem { Content = "Always" });
        RestorePointBox.SelectedIndex = (int)RestorePoint.HighRisk;
        QuietSwitch.IsOn = true;
        QuietNote.Text = QuietNoteText(_controller);
    }

    /// <summary>
    /// Whether the program has a quiet uninstaller is known only once Purge has recorded it (its commands come with
    /// the record); before that the note says so instead of claiming there is none.
    /// </summary>
    private static string QuietNoteText(UninstallController controller) =>
        controller.Command is null
            ? "Purge reads whether this program has a quiet uninstaller when it records it. Quiet mode is used when it has one."
            : controller.QuietAvailable
                ? "Quiet mode skips the program's own dialogs. Purge never answers \"Keep my settings?\" for you."
                : "This program names no quiet uninstaller, so its own dialogs will appear.";

    private void OnOpenPrograms(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("programs");

    private void Render()
    {
        if (_rendering) return;
        _rendering = true;
        try
        {
            var controller = _controller;
            var name = controller.Target?.ProgramName;
            // The empty state only while no program was started; a queue always starts its first program, so a
            // waiting queue's "Next" card (outside RunGrid) is never hidden by it.
            var hasTarget = controller.Target is not null;
            EmptyCard.Visibility = hasTarget ? Visibility.Collapsed : Visibility.Visible;
            RunGrid.Visibility = hasTarget ? Visibility.Visible : Visibility.Collapsed;
            SubtitleText.Text = (name is { Length: > 0 } ? name : "Nothing is running")
                                + (hasTarget && _queue.PositionText is { } position ? " · " + position : "");
            ProgramNameText.Text = name is { Length: > 0 } ? name : "No program selected";
            ProgramInitial.Text = name is { Length: > 0 } ? name[..1].ToUpperInvariant() : "?";
            if (name is { Length: > 0 }) ProgramTile.Background = ProgramRow.TileFor(name);

            RouteText.Text = controller.RouteText ?? "Waiting";
            RouteChip.Visibility = controller.RouteText is null ? Visibility.Collapsed : Visibility.Visible;
            RouteDetailText.Text = controller.Target is null
                ? "Pick a program in Programs and choose Uninstall."
                : controller.RouteText is { } route
                    ? (controller.StateOf(UninstallStep.Run) == StepState.Pending
                        ? $"Its uninstaller will run at {route.ToLowerInvariant()}."
                        : $"Its uninstaller ran at {route.ToLowerInvariant()}.")
                    : controller.LaunchState == UninstallLaunchState.Cancelled
                        ? "Not started: administrator permission was not given."
                        : controller.IsBusy
                            ? controller.LaunchState is null
                                ? "Purge is asking for administrator permission."
                                : "Purge is recording the program."
                            : "Not started.";

            CommandText.Text = controller.SelectedCommand ?? "";
            CommandText.Visibility = controller.SelectedCommand is null ? Visibility.Collapsed : Visibility.Visible;
            SignerText.Text = controller.Signer is { Length: > 0 } signer
                ? "Signed by " + signer
                : "No signature Purge can name.";
            SignerText.Visibility = controller.SelectedCommand is null ? Visibility.Collapsed : Visibility.Visible;

            RenderSteps();
            RenderRunning();
            RenderChoices();
            RenderBars();
            RenderQueue();
            if (controller.IsBusy != _wasBusy)
            {
                _wasBusy = controller.IsBusy;
                MainWindow.Instance.OnHeldScanChanged();
                MainWindow.Instance.Programs.OnBrokerUsersChanged();
                MainWindow.Instance.UpdateBadges();
            }
            FooterText.Text = controller.Target is null
                ? controller.GuideText
                : controller.CurrentStep == UninstallStep.Ready
                    ? "The scan is in. The leftovers page shows what Purge found; nothing moves until you confirm there."
                    : "Nothing is moved or removed by Purge until you confirm the list on the leftovers page.";
        }
        finally
        {
            _rendering = false;
        }
    }

    private void RenderSteps()
    {
        foreach (var (step, _) in StepTitles)
        {
            var row = _rows[step];
            var state = _controller.StateOf(step);
            var (glyph, brush) = state switch
            {
                StepState.Done => ("\u2713", DoneBrush),
                StepState.Active => ("\u25CF", DoneBrush),
                StepState.Warning => ("\u0021", WarningBrush),
                StepState.Failed => ("\u00D7", ErrorBrush),
                _ => ("\u25CB", PendingBrush),
            };
            row.Glyph.Text = glyph;
            row.Glyph.Foreground = brush;
            // A null Foreground is not "inherit" but no brush at all (the title went invisible): clear the local
            // value so the theme's text brush applies again.
            if (state is StepState.Warning or StepState.Failed) row.Title.Foreground = brush;
            else row.Title.ClearValue(TextBlock.ForegroundProperty);
            var detail = _controller.DetailOf(step);
            row.Detail.Text = detail ?? "";
            row.Detail.Visibility = string.IsNullOrEmpty(detail) ? Visibility.Collapsed : Visibility.Visible;
        }
    }

    private void RenderRunning()
    {
        var running = _controller.Running;
        RunningCard.Visibility = running.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (running.Count == 0) return;
        var names = running.Select(p => p.Name).Where(n => n.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var what = names.Count == 0 ? "A program" : string.Join(", ", names);
        RunningText.Text = what + (running.Count == 1 ? " is still running" : $" ({running.Count} processes) is still running")
                           + " from the program's folder. Its files are in use.";
        var checkRunning = CheckRunning;
        RunningRetry.IsEnabled = !_controller.IsBusy && !checkRunning;
        ToolTipService.SetToolTip(RunningRetry, checkRunning ? CheckRunningHint : null);
    }

    private void RenderChoices()
    {
        var controller = _controller;
        var checkRunning = CheckRunning;
        var hint = checkRunning ? CheckRunningHint : null;
        // The switch shows only for a program with a quiet uninstaller: a disabled switch said nothing the note
        // below does not, and before the program is recorded nobody knows yet.
        QuietRow.Visibility = controller.QuietAvailable ? Visibility.Visible : Visibility.Collapsed;
        QuietSwitch.IsEnabled = controller.QuietAvailable && !controller.IsBusy && !checkRunning;
        ToolTipService.SetToolTip(QuietSwitch, hint);
        ToolTipService.SetToolTip(RestorePointBox, hint);
        if (QuietSwitch.IsOn != controller.Quiet) QuietSwitch.IsOn = controller.Quiet;
        QuietNote.Text = QuietNoteText(controller);
        RestorePointBox.IsEnabled = !controller.IsBusy && !checkRunning;
        var wanted = (int)controller.RestorePoint;
        if (RestorePointBox.SelectedIndex != wanted) RestorePointBox.SelectedIndex = wanted;
    }

    private void RenderBars()
    {
        BarsHost.Children.Clear();
        foreach (var notice in _controller.Notices)
            BarsHost.Children.Add(BuildBar(notice));
        // The disabled actions' tooltips do not show (a disabled control gets no pointer events), so say it in a line.
        if (CheckRunning && _controller.Target is not null)
        {
            var bar = BuildBar(new UninstallNotice(UninstallNoticeKind.Info, "Waiting for a leftovers check.", CheckRunningHint));
            bar.IsClosable = false;
            BarsHost.Children.Add(bar);
        }
        // The pipeline ran again or started anew while a scan waited (it cleared or replaced its outcome): that scan
        // is gone, so say so.
        if (_heldOutcome is { } held && !ReferenceEquals(held, _controller.CompletedOutcome)) DropHeld(held);
        if (_handedQuietly is { } quiet && !ReferenceEquals(quiet, _controller.CompletedOutcome)) _handedQuietly = null;
        if (_heldOutcome is { } waiting)
        {
            // The broker ends after ten minutes without a request (bins/purge-broker/src/lifetime.rs, IDLE_LIMIT),
            // and the held scan with it.
            var changing = LeftoversNavigator.IsChanging;
            var bar = BuildBar(new UninstallNotice(UninstallNoticeKind.Warning, "The scan is ready.",
                (changing
                    ? "The Leftovers page is still applying another change, so this scan waits here and opens there when "
                      + "that change has finished. "
                    : "The Leftovers page has finished its change and shows its outcome, so this scan waits until you show "
                      + "it there. ")
                + "It is kept for about 10 minutes; after that, start the uninstall again. Nothing was moved."));
            var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 8, 0, 0) };
            var show = ActionButton("Show leftovers", ShowHeldNow);
            show.IsEnabled = !changing && !_controller.IsBusy;
            actions.Children.Add(show);
            bar.Content = actions;
            bar.IsClosable = false;
            BarsHost.Children.Add(bar);
        }
        if (_handedQuietly is { } handed)
        {
            var bar = BuildBar(new UninstallNotice(UninstallNoticeKind.Info, "The scan is on the Leftovers page.",
                $"The Leftovers page finished its change, so the scan of {NameOf(handed)} went there. Nothing was moved."));
            var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 8, 0, 0) };
            actions.Children.Add(ActionButton("Show leftovers", () =>
            {
                _handedQuietly = null;
                MainWindow.Instance.Navigate("leftovers");
            }));
            bar.Content = actions;
            bar.Closed += (_, _) => _handedQuietly = null;
            BarsHost.Children.Add(bar);
        }
        if (_droppedHeld is { } dropped)
        {
            var bar = BuildBar(new UninstallNotice(UninstallNoticeKind.Info, "The waiting scan was closed.",
                (_droppedRerun
                    ? $"The uninstall of {dropped} ran again, so its scan that waited for the Leftovers page was closed. "
                    : $"A new uninstall started, so the scan of {dropped} that waited for the Leftovers page was closed. ")
                + "Nothing was moved."));
            bar.Closed += (_, _) => _droppedHeld = null;
            BarsHost.Children.Add(bar);
        }
    }

    /// <summary>Forgets a held scan the pipeline no longer has and keeps a bar that says so.</summary>
    private void DropHeld(UninstallOutcome held)
    {
        SetHeld(null);
        _droppedHeld = NameOf(held);
        _droppedRerun = _controller.Target is { } target && target.ProgramId == held.Target.ProgramId;
    }

    private InfoBar BuildBar(UninstallNotice notice)
    {
        var bar = new InfoBar
        {
            Severity = notice.Kind switch
            {
                UninstallNoticeKind.Info => InfoBarSeverity.Informational,
                UninstallNoticeKind.Warning => InfoBarSeverity.Warning,
                _ => InfoBarSeverity.Error,
            },
            Title = notice.Title,
            Message = notice.Message,
            IsOpen = true,
            IsClosable = true,
            RequestedTheme = MainWindow.Instance.ActualTheme,
        };
        var actions = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8, Margin = new Thickness(0, 8, 0, 0) };
        // Each of these can start the broker; while a removed program's check has one, they wait.
        if (notice.CanForce)
            actions.Children.Add(BrokerActionButton("Run forced cleanup", () => _ = _controller.ForceAsync()));
        if (notice.CanRetry)
            // An informational bar's retry is a declined or cancelled admin prompt: nothing failed, so "Try again".
            actions.Children.Add(BrokerActionButton(notice.Kind == UninstallNoticeKind.Info ? "Try again" : "Retry",
                () => _ = _controller.RetryAsync()));
        if (notice.CanStartOver)
            actions.Children.Add(BrokerActionButton("Start over", () => _ = _controller.StartOverAsync()));
        if (actions.Children.Count > 0) bar.Content = actions;
        return bar;
    }

    private static Button ActionButton(string text, Action action)
    {
        var button = new Button { Content = text, MinHeight = 32 };
        button.Click += (_, _) => action();
        AutomationProperties.SetName(button, text);
        return button;
    }

    /// <summary>An action that can start the broker: disabled, with a tooltip, while a removed program's check runs.</summary>
    private static Button BrokerActionButton(string text, Action action)
    {
        var button = ActionButton(text, () =>
        {
            if (!CheckRunning) action();
        });
        if (CheckRunning)
        {
            button.IsEnabled = false;
            ToolTipService.SetToolTip(button, CheckRunningHint);
        }
        return button;
    }

    private void OnRecheck(object sender, RoutedEventArgs e)
    {
        if (CheckRunning) return;
        _ = _controller.RecheckAsync();
    }

    private void OnQuietToggled(object sender, RoutedEventArgs e)
    {
        if (_rendering) return;
        _controller.SetChoice(QuietSwitch.IsOn, _controller.RestorePoint);
    }

    private void OnRestorePointChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_rendering) return;
        var choice = (RestorePoint)Math.Clamp(RestorePointBox.SelectedIndex, 0, 2);
        _controller.SetChoice(_controller.Quiet, choice);
    }

    private void OnConfirmationRequested(UninstallConfirmation confirmation) =>
        DispatcherQueue.TryEnqueue(() => _ = ShowConfirmationAsync(confirmation));

    private async Task ShowConfirmationAsync(UninstallConfirmation confirmation)
    {
        try
        {
            var root = MainWindow.Instance.DialogRoot;
            if (root is null)
            {
                await _controller.AnswerAsync(new UninstallAnswer(false, confirmation.Quiet, confirmation.RestorePoint));
                return;
            }

            var content = new StackPanel { Spacing = 8, MaxWidth = 540 };
            content.Children.Add(new TextBlock { Text = "Purge will:", FontWeight = FontWeights.SemiBold });
            for (var i = 0; i < confirmation.Steps.Count; i++)
                content.Children.Add(new TextBlock
                {
                    Text = $"{i + 1}. {confirmation.Steps[i]}",
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 13,
                });

            content.Children.Add(new TextBlock { Text = "Command", FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 6, 0, 0) });
            var commandText = new TextBlock
            {
                Text = confirmation.Quiet && confirmation.QuietCommand is { Length: > 0 } ? confirmation.QuietCommand : confirmation.Command,
                FontFamily = new FontFamily("Cascadia Mono, Consolas"),
                FontSize = 12.5,
                TextWrapping = TextWrapping.Wrap,
                IsTextSelectionEnabled = true,
            };
            content.Children.Add(commandText);
            content.Children.Add(new TextBlock
            {
                Text = confirmation.Signer is { Length: > 0 } signer ? "Signed by " + signer : "No signature Purge can name.",
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Foreground = PendingBrush,
            });

            if (confirmation.Running.Count > 0)
            {
                var names = confirmation.Running.Select(p => p.Name).Where(n => n.Length > 0)
                    .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
                content.Children.Add(new TextBlock
                {
                    Text = "Still running: " + string.Join(", ", names)
                           + ". Close it yourself; Purge never closes a program for you. Check again once it is closed.",
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 12,
                    Foreground = WarningBrush,
                });
            }

            var quiet = new ToggleSwitch
            {
                IsOn = confirmation.QuietAvailable && confirmation.Quiet,
                IsEnabled = confirmation.QuietAvailable,
                OnContent = "",
                OffContent = "",
                MinWidth = 0,
            };
            AutomationProperties.SetName(quiet, "Use quiet mode when available");
            var quietRow = new Grid { Margin = new Thickness(0, 6, 0, 0) };
            quietRow.ColumnDefinitions.Add(new ColumnDefinition());
            quietRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            quietRow.Children.Add(new TextBlock
            {
                Text = confirmation.QuietAvailable ? "Use quiet mode" : "This program has no quiet uninstaller",
                VerticalAlignment = VerticalAlignment.Center,
                TextWrapping = TextWrapping.Wrap,
            });
            Grid.SetColumn(quiet, 1);
            quietRow.Children.Add(quiet);
            content.Children.Add(quietRow);
            quiet.Toggled += (_, _) =>
            {
                commandText.Text = quiet.IsOn && confirmation.QuietCommand is { Length: > 0 }
                    ? confirmation.QuietCommand
                    : confirmation.Command;
            };
            content.Children.Add(new TextBlock
            {
                Text = confirmation.QuietCommand is null
                    ? "Its own dialogs will appear."
                    : "Quiet command: " + confirmation.QuietCommand,
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Foreground = PendingBrush,
            });

            var restore = new ComboBox { Margin = new Thickness(0, 6, 0, 0) };
            restore.Items.Add(new ComboBoxItem { Content = "Off" });
            restore.Items.Add(new ComboBoxItem { Content = "High-risk changes only (default)" });
            restore.Items.Add(new ComboBoxItem { Content = "Always" });
            restore.SelectedIndex = (int)confirmation.RestorePoint;
            AutomationProperties.SetName(restore, "Restore point at the cleanup step");
            content.Children.Add(new TextBlock
            {
                Text = "Restore point for the cleanup step",
                FontWeight = FontWeights.SemiBold,
                Margin = new Thickness(0, 6, 0, 0),
            });
            content.Children.Add(restore);
            content.Children.Add(new TextBlock
            {
                Text = "Nothing is moved or removed by Purge until you confirm the list on the next page.",
                TextWrapping = TextWrapping.Wrap,
                FontSize = 12,
                Foreground = PendingBrush,
            });

            var dialog = new ContentDialog
            {
                XamlRoot = root,
                RequestedTheme = MainWindow.Instance.ActualTheme,
                Title = $"Uninstall {confirmation.Target.ProgramName}?",
                Content = new ScrollViewer { Content = content, MaxHeight = 520 },
                PrimaryButtonText = "Uninstall",
                CloseButtonText = "Not now",
                DefaultButton = ContentDialogButton.Close,
            };
            if (confirmation.Running.Count > 0) dialog.SecondaryButtonText = "Check again";

            var answer = await dialog.ShowAsync();
            var restorePoint = (RestorePoint)Math.Clamp(restore.SelectedIndex, 0, 2);
            if (answer == ContentDialogResult.Secondary)
            {
                await _controller.AnswerAsync(new UninstallAnswer(false, quiet.IsOn, restorePoint, Recheck: true));
                return;
            }
            await _controller.AnswerAsync(new UninstallAnswer(answer == ContentDialogResult.Primary,
                quiet.IsOn && confirmation.QuietAvailable, restorePoint));
        }
        catch (Exception)
        {
            // A dialog that cannot be shown must not leave the pipeline waiting forever.
            await _controller.AnswerAsync(new UninstallAnswer(false, confirmation.Quiet, confirmation.RestorePoint));
        }
    }

    private void OnCompleted(UninstallOutcome outcome) => DispatcherQueue.TryEnqueue(() => HandOff(outcome));

    /// <summary>
    /// Hands the scan and the live broker to the Leftovers page (and shows that page when <paramref name="navigate"/>).
    /// While that page applies another change its link must not be replaced, so the scan waits here (the controller
    /// keeps the broker) behind a "Show leftovers" bar; it is handed over by itself when that change ends and the page
    /// is not on screen (<see cref="OnLeftoversChangingChanged"/>), or when the user leaves the page
    /// (<see cref="OnLeftoversLeft"/>).
    /// </summary>
    private void HandOff(UninstallOutcome outcome, bool navigate = true)
    {
        if (!ReferenceEquals(outcome, _controller.CompletedOutcome))
        {
            // The pipeline started again meanwhile: this scan is no longer the one on the page.
            if (_heldOutcome is { } held) DropHeld(held);
            Render();
            return;
        }
        // A newer scan is in: the bar about an older one that was closed has said what it had to.
        _droppedHeld = null;
        _handedQuietly = null;
        if (LeftoversNavigator.IsChanging)
        {
            SetHeld(outcome);
            Render();
            return;
        }
        SetHeld(null);
        var broker = _controller.TakeBroker();
        var session = (broker as BrokerUninstallClient)?.TakeSession();
        if (broker is not null && session is null) _ = broker.DisposeAsync();
        var request = new LeftoversRequest(outcome.Target.ProgramId, outcome.Target.ProgramName, outcome.SessionId,
            outcome.ScanId, outcome.Mode, outcome.RestorePoint, outcome.Quiet, session);
        var shown = LeftoversNavigator.TryShow(request, navigate);
        if (!shown && session is not null) _ = session.DisposeAsync().AsTask();
        if (shown && !navigate) _handedQuietly = outcome;
        if (broker is not null) _ = broker.DisposeAsync();
        Render();
    }
}
