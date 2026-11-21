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
    private readonly Dictionary<UninstallStep, StepRow> _rows = [];
    private bool _rendering;
    private bool _handoffFailed;

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
        _controller.AdminPromptCancelled += () => DispatcherQueue.TryEnqueue(
            () => MainWindow.Instance.ShowAdminPromptCancelled());

        BuildStepper();
        BuildChoices();
        Render();
    }

    /// <summary>Starts the pipeline for a program chosen on the Programs page.</summary>
    public void Begin(UninstallTarget target)
    {
        _handoffFailed = false;
        ProgramTile.Background = ProgramRow.TileFor(target.ProgramName);
        _ = _controller.BeginAsync(target);
    }

    private async Task<UninstallLaunch> LaunchAsync(CancellationToken ct)
    {
        try
        {
            if (!await MainWindow.Instance.ConfirmFirstElevationAsync())
                return new UninstallLaunch(UninstallLaunchState.Cancelled, null, "", null);
            var result = await BrokerLauncher.LaunchAsync(BrokerLauncher.PathBesideApp(), MainWindow.Instance.Hwnd, ct);
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
        QuietNote.Text = _controller.QuietAvailable
            ? "Quiet mode skips the program's own dialogs. Purge never answers \"Keep my settings?\" for you."
            : "This program names no quiet uninstaller, so its own dialogs will appear.";
    }

    private void Render()
    {
        if (_rendering) return;
        _rendering = true;
        try
        {
            var controller = _controller;
            var name = controller.Target?.ProgramName;
            SubtitleText.Text = name is { Length: > 0 } ? name : "Nothing is running";
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
                    : "Purge is asking for administrator permission.";

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
            row.Title.Foreground = state is StepState.Warning or StepState.Failed ? brush : null;
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
        RunningRetry.IsEnabled = !_controller.IsBusy;
    }

    private void RenderChoices()
    {
        var controller = _controller;
        QuietSwitch.IsEnabled = controller.QuietAvailable && !controller.IsBusy;
        if (QuietSwitch.IsOn != controller.Quiet) QuietSwitch.IsOn = controller.Quiet;
        QuietNote.Text = controller.QuietAvailable
            ? "Quiet mode skips the program's own dialogs. Purge never answers \"Keep my settings?\" for you."
            : "This program names no quiet uninstaller, so its own dialogs will appear.";
        RestorePointBox.IsEnabled = !controller.IsBusy;
        var wanted = (int)controller.RestorePoint;
        if (RestorePointBox.SelectedIndex != wanted) RestorePointBox.SelectedIndex = wanted;
    }

    private void RenderBars()
    {
        BarsHost.Children.Clear();
        foreach (var notice in _controller.Notices)
            BarsHost.Children.Add(BuildBar(notice));
        if (_handoffFailed)
        {
            BarsHost.Children.Add(new InfoBar
            {
                Severity = InfoBarSeverity.Warning,
                Title = "The leftovers page is not ready in this build.",
                Message = "The uninstaller ran and the scan is in, but this page cannot show the list yet.",
                IsOpen = true,
                IsClosable = true,
                RequestedTheme = MainWindow.Instance.ActualTheme,
            });
        }
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
        if (notice.CanForce)
            actions.Children.Add(ActionButton("Run forced cleanup", () => _ = _controller.ForceAsync()));
        if (notice.CanRetry)
            actions.Children.Add(ActionButton("Retry", () => _ = _controller.RetryAsync()));
        if (notice.CanStartOver)
            actions.Children.Add(ActionButton("Start over", () => _ = _controller.StartOverAsync()));
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

    private void OnRecheck(object sender, RoutedEventArgs e) => _ = _controller.RecheckAsync();

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

    private void OnCompleted(UninstallOutcome outcome) => DispatcherQueue.TryEnqueue(() =>
    {
        var broker = _controller.TakeBroker();
        var session = (broker as BrokerUninstallClient)?.TakeSession();
        if (broker is not null && session is null) _ = broker.DisposeAsync();
        var request = new LeftoversRequest(outcome.Target.ProgramId, outcome.Target.ProgramName, outcome.SessionId,
            outcome.ScanId, outcome.Mode, outcome.RestorePoint, outcome.Quiet, session);
        _handoffFailed = !LeftoversNavigator.Show(request);
        if (broker is not null) _ = broker.DisposeAsync();
        Render();
    });
}
