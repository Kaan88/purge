using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Purge.App.Shell;
using Purge.Client.Broker;
using Purge.Client.Rpc;
using RpcExecResult = Purge.Client.Rpc.ExecResult;
using RpcUndoResult = Purge.Client.Rpc.UndoResult;

namespace Purge.App.Views;

/// <summary>
/// S3: the leftovers review over the broker (design 7a, 9.4), its waiting state (design 8.1) and its
/// result page (design 6.4). The state and every rule live in <see cref="LeftoversViewModel"/>; this
/// class only draws it and forwards clicks.
/// </summary>
public sealed partial class LeftoversView : UserControl, ILeftoversPage
{
    private static readonly Brush Explicit = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0x2E, 0x9E, 0x44));
    private static readonly Brush Warning = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0xD1, 0x34, 0x38));
    private static readonly Brush Note = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0x8A, 0x8A, 0x8A));

    private LeftoversViewModel? _vm;
    private LeftoversRequest? _request;
    private BrokerSession? _ownedBroker;
    private bool _explaining;

    /// <summary>The empty page's words: where an uninstall starts, and where a program removed without Purge is checked.</summary>
    private const string NoScanText =
        "Start an uninstall on the Programs page; Purge shows this page after the uninstaller has run. A program removed "
        + "without Purge can be checked from Programs, under \"Removed outside Purge\".";

    public LeftoversView()
    {
        InitializeComponent();
        if (!Program.Engine.IsLive)
        {
            Use(new LeftoversViewModel(new OfflineBroker()));
            // The launch bench's S3 timer (--bench-s3 N) opens the page on an N-item fixture.
            var benchItems = Program.Options.BenchS3Items;
            _vm!.LoadSample(count: benchItems);
            if (benchItems > 0 && LaunchMarkers.Enabled)
            {
                var seen = false;
                Items.ContainerContentChanging += (_, _) =>
                {
                    if (seen) return;
                    seen = true;
                    MainWindow.Instance.MarkAfterNextFrame("s3_open");
                };
            }
        }
        else
        {
            ShowEmpty("No scan yet", NoScanText);
        }
    }

    /// <summary>The items of a scan that wait for review here (the rail's badge); 0 outside the review.</summary>
    public int WaitingForReview => _vm is { Phase: LeftoversPhase.Review } vm ? vm.Items.Count : 0;

    /// <summary>The page's state, for the shell and the tests.</summary>
    public LeftoversViewModel? ViewModel => _vm;

    /// <summary>True while the page applies a change over its broker link (<see cref="LeftoversViewModel.IsChanging"/>).</summary>
    public bool IsChanging => _vm?.IsChanging == true;

    /// <summary>
    /// S2's hand-off: the scan is already made, so this pages <c>scan.candidates</c> for it and takes the broker
    /// link (the caller no longer closes it). The page keeps <see cref="LeftoversRequest.RestorePoint"/> for
    /// <c>plan.execute</c>. While a change is on its way the request is refused (<see cref="LeftoversNavigator.TryShow"/>
    /// checks first) and its new link is closed: ending the running change's link would leave its outcome unknown.
    /// </summary>
    public void Show(LeftoversRequest request)
    {
        if (IsChanging)
        {
            if (request.Broker is { } refused && !ReferenceEquals(refused, _ownedBroker)) _ = refused.DisposeAsync().AsTask();
            return;
        }
        var previous = _ownedBroker;
        _ownedBroker = request.Broker;
        if (previous is not null && !ReferenceEquals(previous, request.Broker))
            _ = previous.DisposeAsync().AsTask();

        _request = request;
        if (request.Broker is null)
        {
            Use(new LeftoversViewModel(new OfflineBroker()));
            ShowEmpty("The administrator part ended",
                "The scan cannot be shown because its broker link is gone. Start the uninstall again from the Uninstall pipeline page.");
            return;
        }
        var broker = new LeftoversBroker(request.Broker.Rpc) { AllowForeground = request.Broker.AllowForeground };
        Use(new LeftoversViewModel(broker, request.Broker.AllowForeground, CurrentUserSid()));
        _ = _vm!.ShowRequestAsync(request);
    }

    /// <summary>The app's (unelevated, signed-in) user, so registry rows under that SID read "Your account".</summary>
    private static string? CurrentUserSid()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return identity.User?.Value;
        }
        catch (System.Security.SecurityException)
        {
            return null;
        }
    }

    private void Use(LeftoversViewModel vm)
    {
        if (_vm is not null) _vm.Changed -= OnViewModelChanged;
        _vm = vm;
        _vm.Changed += OnViewModelChanged;
        DispatcherQueue.TryEnqueue(Refresh);
    }

    private void OnViewModelChanged() => DispatcherQueue.TryEnqueue(Refresh);

    private bool _wasChanging;

    private void Refresh()
    {
        // One broker at a time: the Programs page's checks and a scan the Uninstall page holds wait for a change to
        // end, so they hear when it starts and ends.
        if (IsChanging != _wasChanging)
        {
            _wasChanging = IsChanging;
            MainWindow.Instance.OnLeftoversChangingChanged();
        }
        MainWindow.Instance.UpdateBadges();
        if (_vm is not { } vm) return;
        var name = vm.ProgramName.Length > 0 ? vm.ProgramName : _request?.ProgramName ?? "";
        TitleText.Text = name.Length > 0 ? $"Leftovers of {name}" : "Leftovers";
        // The program's tile only when there is a program; no placeholder letter on the empty page.
        AppTile.Visibility = Vis(name.Length > 0 && vm.Phase != LeftoversPhase.Empty);
        if (name.Length > 0)
        {
            AppInitial.Text = name[..1].ToUpperInvariant();
            AppTile.Background = ProgramRow.TileFor(name);
        }
        SubtitleText.Text = Subtitle(vm);

        var review = vm.Phase == LeftoversPhase.Review;
        ListButtons.Visibility = Vis(review);
        ReviewPanel.Visibility = Vis(review);
        Footer.Visibility = Vis(review);
        WaitingPanel.Visibility = Vis(vm.Phase == LeftoversPhase.Waiting);
        ResultPanel.Visibility = Vis(vm.Phase == LeftoversPhase.Result);
        UndonePanel.Visibility = Vis(vm.Phase == LeftoversPhase.Undone);
        EmptyPanel.Visibility = Vis(vm.Phase == LeftoversPhase.Empty);

        ShowBars(vm);
        if (review) RefreshList(vm);
        if (vm.Phase == LeftoversPhase.Waiting) RefreshWaiting(vm);
        if (vm.Phase == LeftoversPhase.Result) RefreshResult(vm);
        if (vm.Phase == LeftoversPhase.Undone) RefreshUndone(vm);
        if (vm.Phase == LeftoversPhase.Interrupted) ShowEmpty("A change was interrupted", vm.Error ?? "The administrator part ended.");
    }

    private string Subtitle(LeftoversViewModel vm) => vm.Phase switch
    {
        LeftoversPhase.Scanning => vm.ScanProgress.Length > 0 ? "Scanning: " + vm.ScanProgress : "Scanning…",
        LeftoversPhase.Waiting => "Waiting for the security prompt",
        LeftoversPhase.Result => "The result is in · restorable from History & undo",
        LeftoversPhase.Undone => "Put back",
        LeftoversPhase.Interrupted => "Interrupted · check History & undo",
        LeftoversPhase.Review => vm.Scan is { } scan
            ? $"{scan.Mode switch { ScanMode.Post => "Post-uninstall scan", ScanMode.Forced => "Forced scan", _ => "Stored-fingerprint scan" }} · " +
              $"{vm.Items.Count.ToString(CultureInfo.CurrentCulture)} items"
            : "Review the list",
        _ => "No scan yet",
    };

    private void RefreshList(LeftoversViewModel vm)
    {
        var selected = (Items.SelectedItem as LeftoversRow)?.Item?.CandidateId;
        var rows = new List<LeftoversRow>();
        foreach (var group in vm.VisibleGroups())
        {
            rows.Add(LeftoversRow.ForGroup(group, vm.HiddenCount(group)));
            if (!group.Expanded) continue;
            foreach (var item in vm.VisibleItems(group)) rows.Add(LeftoversRow.ForItem(item));
        }
        Items.ItemsSource = rows;
        if (selected is { Length: > 0 })
        {
            var again = rows.FirstOrDefault(r => r.Item?.CandidateId == selected);
            if (again is not null) Items.SelectedItem = again;
        }
        UpdateCounts(vm);
        UpdateMove(vm);
        ExpandButton.Content = vm.Groups.Any(g => !g.Expanded) ? "Expand all" : "Collapse all";
        WeakButton.Content = vm.ShowWeak ? $"Hide weak matches ({vm.WeakCount})" : $"Show weak matches ({vm.WeakCount})";
        WeakButton.Visibility = Vis(vm.WeakCount > 0);
    }

    /// <summary>
    /// The Move button. Sample data has no broker, so nothing can be moved: the button stays off and the footer says
    /// why in words (a disabled button shows no tooltip).
    /// </summary>
    private void UpdateMove(LeftoversViewModel vm)
    {
        MoveButton.IsEnabled = vm.CanMove && !vm.IsSample;
        MoveText.Text = vm.MoveText;
        // "Delete instead of keeping in quarantine": a request only, off by default (DECISIONS 2026-11-24).
        DeleteAfterBox.Content = LeftoversViewModel.DeleteAfterText;
        DeleteAfterBox.IsChecked = vm.DeleteAfter;
        DeleteAfterBox.IsEnabled = !vm.IsSample;
        ToolTipService.SetToolTip(DeleteAfterBox, LeftoversViewModel.DeleteAfterHelp);
        FooterHint.Text = vm.IsSample
            ? "Sample data: nothing can be moved"
            : vm.DeleteAfter ? LeftoversViewModel.TwoPromptsHint
            : "You'll confirm in the Purge security prompt";
        ToolTipService.SetToolTip(MoveButton, vm.IsSample ? "Sample data: nothing can be moved." : null);
    }

    private void UpdateCounts(LeftoversViewModel vm)
    {
        var candidates = vm.Items;
        var safe = candidates.Count(i => i.Band == Band.Safe);
        var likely = candidates.Count(i => i.Band is Band.Likely or Band.Weak);
        var protect = candidates.Count(i => i.Band == Band.Protected);
        SafePill.Text = $"Safe {safe} · {LeftoverItemModel.FormatSize(Sum(candidates, Band.Safe))}";
        LikelyPill.Text = $"Likely {likely} · {LeftoverItemModel.FormatSize(Sum(candidates, Band.Likely, Band.Weak))}";
        ProtectedPill.Text = $"Protected {protect}";
        BarSafe.Width = new GridLength(Math.Max(safe, 0.01), GridUnitType.Star);
        BarLikely.Width = new GridLength(Math.Max(likely, 0.01), GridUnitType.Star);
        BarProtected.Width = new GridLength(Math.Max(protect, 0.01), GridUnitType.Star);

        FooterCount.Text = $"{vm.SelectedCount} of {vm.SelectableCount} selected";
        VerdictText.Text = $"{vm.SelectedCount} {(vm.SelectedCount == 1 ? "item" : "items")} · {LeftoverItemModel.FormatSize(vm.SelectedBytes)}";
        var parts = new List<string> { LeftoverItemModel.FormatSize(vm.SelectedBytes) };
        var chosen = candidates.Where(i => i.Checked && i.Selectable).ToList();
        AddPart(parts, chosen.Count(i => i.Kind is ItemKind.File or ItemKind.Folder), "file item", "file items");
        AddPart(parts, chosen.Count(i => i.Kind is ItemKind.RegistryKey or ItemKind.RegistryValue or ItemKind.RegistryData),
            "registry item", "registry items");
        AddPart(parts, chosen.Count(i => i.Kind is ItemKind.Task or ItemKind.Service or ItemKind.FirewallRule),
            "task or service", "tasks and services");
        FooterDetail.Text = " · " + string.Join(", ", parts);
    }

    private static ulong Sum(List<LeftoverItemModel> items, params Band[] bands) =>
        items.Where(i => bands.Contains(i.Band)).Aggregate(0UL, (sum, item) => sum + (item.SizeBytes ?? 0));

    private static void AddPart(List<string> parts, int n, string one, string many)
    {
        if (n > 0) parts.Add($"{n} {(n == 1 ? one : many)}");
    }

    private void ShowBars(LeftoversViewModel vm)
    {
        InfoBarHost.Children.Clear();
        if (vm.Error is { Length: > 0 } error)
            AddInfoBar(InfoBarSeverity.Error, "The administrator part refused or failed.", error);
        else if (vm.Info is { Length: > 0 } info)
            AddInfoBar(InfoBarSeverity.Informational, "", info);

        if (vm.RefusalLines.Count > 0)
        {
            var text = string.Join(" · ", vm.RefusalLines.Take(5));
            if (vm.RefusalLines.Count > 5) text += $" · and {vm.RefusalLines.Count - 5} more";
            AddInfoBar(InfoBarSeverity.Warning, "Some selected items cannot be quarantined.", text);
        }
        if (vm.RescanOffered)
        {
            var bar = AddInfoBar(InfoBarSeverity.Informational, "The local baseline finished building.",
                "Scan again to apply what the new baseline learned. Your ticks are kept by item id.");
            var again = new Button { Content = "Scan again" };
            again.Click += async (_, _) => { if (_vm is { } current) await current.RescanAsync(); };
            bar.ActionButton = again;
        }
        if (vm.RescanMessage is { Length: > 0 } rescan)
            AddInfoBar(InfoBarSeverity.Success, "Scanned again.", rescan);
        if (vm.Phase == LeftoversPhase.Review && vm.IsSample)
            AddInfoBar(InfoBarSeverity.Informational, "Sample data.",
                "This list is an example, not a scan of this PC. Nothing can be moved from it.");
        // A forced scan ticks nothing on purpose (engine rule): say so, so the empty ticks do not read as a fault.
        else if (vm.Phase == LeftoversPhase.Review && vm.IsForced)
            AddInfoBar(InfoBarSeverity.Informational, "Nothing is ticked for you.",
                "The uninstaller failed or Purge could not check that the program is gone, so this is a forced scan: "
                + "Purge ticks nothing, not even Safe items. Tick what you want moved.");
        ShowHeldBar();
    }

    private InfoBar? _heldBar;

    /// <summary>The Uninstall page started or stopped holding a scan for this page: its line follows it.</summary>
    public void OnHeldScanChanged() => DispatcherQueue.TryEnqueue(ShowHeldBar);

    /// <summary>
    /// The line for a scan the Uninstall page holds for this page: it does not replace a change's outcome on screen,
    /// so it says when it comes (when the user goes to another page) and offers it now once no change runs.
    /// </summary>
    private void ShowHeldBar()
    {
        ShowQueueBar();
        if (_heldBar is not null) InfoBarHost.Children.Remove(_heldBar);
        _heldBar = null;
        if (_vm is null || MainWindow.Instance.HeldScanProgram is not { } name) return;
        var changing = IsChanging;
        var bar = new InfoBar
        {
            Severity = InfoBarSeverity.Informational,
            Title = $"A scan of {name} is waiting for this page.",
            Message = changing
                ? "It opens here when this change has finished, but not over its outcome: while you are on this page it "
                  + "waits until you go to another page or choose Show the scan."
                : "It takes this page's place when you go to another page, or now with Show the scan, so you can read "
                  + "this page first.",
            IsOpen = true,
            IsClosable = false,
            RequestedTheme = MainWindow.Instance.ActualTheme,
        };
        if (!changing)
        {
            var show = new Button { Content = "Show the scan" };
            show.Click += (_, _) => MainWindow.Instance.ShowHeldScan();
            bar.ActionButton = show;
        }
        InfoBarHost.Children.Insert(0, bar);
        _heldBar = bar;
    }

    private InfoBar? _queueBar;

    /// <summary>
    /// "Uninstall N" queued more programs: a line says which comes next and takes the user back to the Uninstall page,
    /// where it starts.
    /// </summary>
    private void ShowQueueBar()
    {
        if (_queueBar is not null) InfoBarHost.Children.Remove(_queueBar);
        _queueBar = null;
        if (_vm is null || MainWindow.Instance.HeldScanProgram is not null) return;
        if (UninstallView.Built?.QueuedNext is not { } next) return;
        var bar = new InfoBar
        {
            Severity = InfoBarSeverity.Informational,
            Title = "Next to uninstall: " + next + ".",
            Message = "Finish here first if you like. It starts from the Uninstall page when you choose.",
            IsOpen = true,
            IsClosable = true,
            RequestedTheme = MainWindow.Instance.ActualTheme,
        };
        var go = new Button { Content = "Go to Uninstall" };
        go.Click += (_, _) => MainWindow.Instance.OpenUninstall();
        bar.ActionButton = go;
        bar.Closed += (s, _) => InfoBarHost.Children.Remove(s);
        InfoBarHost.Children.Insert(0, bar);
        _queueBar = bar;
    }

    private InfoBar AddInfoBar(InfoBarSeverity severity, string title, string message)
    {
        var bar = new InfoBar { Severity = severity, Title = title, Message = message, IsOpen = true, IsClosable = true };
        bar.RequestedTheme = MainWindow.Instance.ActualTheme;
        bar.Closed += (s, _) => InfoBarHost.Children.Remove(s);
        InfoBarHost.Children.Add(bar);
        return bar;
    }

    private void RefreshWaiting(LeftoversViewModel vm)
    {
        WaitingTitleText.Text = vm.WaitingTitle;
        WaitingDetailText.Text = vm.WaitingDetail;
        var hasCode = vm.Code is { Length: > 0 };
        WaitingCodeText.Text = hasCode ? vm.Code : "—";
        AttentionExpander.Visibility = Vis(vm.Attention.Count > 0);
        AttentionList.ItemsSource = vm.Attention;
        AttentionExpander.Header = $"Items that need attention ({vm.Attention.Count})";
    }

    private void RefreshResult(LeftoversViewModel vm)
    {
        ResultTitleText.Text = vm.ResultTitle ?? "The move finished";
        ResultDetailText.Text = vm.ResultDetail ?? "";
        DeleteAfterResultText.Text = vm.DeleteAfterResult ?? "";
        DeleteAfterResultText.Visibility = Vis(vm.DeleteAfterResult is { Length: > 0 });
        RestorePointText.Text = vm.RestorePointText ?? "";
        RestorePointText.Visibility = Vis(vm.RestorePointText is { Length: > 0 });
        HeldHost.Visibility = Vis(vm.HeldLines.Count > 0);
        HeldList.ItemsSource = vm.HeldLines;
        FailedHost.Visibility = Vis(vm.FailedLines.Count > 0);
        FailedList.ItemsSource = vm.FailedLines;
        UndoAllButton.Visibility = Vis(vm.CanUndo);
        UndoAllButton.Content = vm.UndoText;
        RetryHeldButton.Visibility = Vis(vm.CanRetryHeld);
        ResultIcon.Glyph = vm.Result?.Outcome == Outcome.Complete ? "\uE73E" : "\uE7BA";
        ResultIcon.Foreground = vm.Result?.Outcome == Outcome.Complete ? Explicit : Warning;
    }

    private void RefreshUndone(LeftoversViewModel vm)
    {
        UndoTitleText.Text = vm.UndoTitle ?? "Put back";
        UndoDetailText.Text = vm.UndoDetail ?? "";
        ConflictList.ItemsSource = vm.UndoConflictLines;
    }

    private void ShowEmpty(string title, string text)
    {
        ReviewPanel.Visibility = Visibility.Collapsed;
        Footer.Visibility = Visibility.Collapsed;
        WaitingPanel.Visibility = Visibility.Collapsed;
        ResultPanel.Visibility = Visibility.Collapsed;
        UndonePanel.Visibility = Visibility.Collapsed;
        EmptyPanel.Visibility = Visibility.Visible;
        ListButtons.Visibility = Visibility.Collapsed;
        AppTile.Visibility = Visibility.Collapsed;
        EmptyTitle.Text = title;
        EmptyText.Text = text;
    }

    private void ShowDetail(LeftoversRow row)
    {
        if (row.Item is not { } item) return;
        DNone.Visibility = Visibility.Collapsed;
        DBody.Visibility = Visibility.Visible;
        DTitle.Text = item.Label is { } label ? label.Title : "";
        DTitle.Visibility = Vis(item.Label is not null);
        DPath.Text = item.DisplayName;
        DSafe.Visibility = Vis(item.Band == Band.Safe);
        DLikely.Visibility = Vis(item.Band == Band.Likely);
        DWeak.Visibility = Vis(item.Band == Band.Weak);
        DProtected.Visibility = Vis(item.IsProtected);
        DUserData.Visibility = Vis(item.IsUserData);
        DPreselect.Text = item.IsProtected ? "Never removed" : item.Refused ? "Cannot be quarantined" : item.Checked ? "Ticked" : "Not ticked";
        DRefused.Text = item.Refused ? "Cannot be quarantined: " + item.RefusalReason : "";
        DRefused.Visibility = Vis(item.Refused);
        var evidence = new List<EvidenceLine>();
        foreach (var line in item.Blockers) evidence.Add(new EvidenceLine("\u26A0", Warning, line));
        foreach (var line in item.Evidence) evidence.Add(new EvidenceLine("\u25CF", Explicit, line));
        if (evidence.Count == 0)
        {
            evidence.Add(item.Band switch
            {
                Band.Protected => new EvidenceLine("\u25CB", Note, item.Why),
                Band.Weak => new EvidenceLine("\u25CB", Note, "Name matches only; never ticked for you."),
                _ => new EvidenceLine("\u25CF", Explicit, item.Why),
            });
        }
        DEvidence.ItemsSource = evidence;
        DContents.Text = item.SizeText.Length > 0 ? item.SizeText : "—";
        DIfRemoved.Text = item.IsProtected
            ? "Purge never removes it"
            : item.Refused ? "Cannot be quarantined: " + item.RefusalReason
            : "Moved to quarantine, restorable from History & undo";
        DFoundBy.Text = item.KindText;
        DOwner.Text = item.OwnerProgram is { Length: > 0 } owner ? "Shared with " + owner + "." : "";
        DOwner.Visibility = Vis(item.OwnerProgram is { Length: > 0 });
    }

    private static Visibility Vis(bool on) => on ? Visibility.Visible : Visibility.Collapsed;

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Items.SelectedItem is not LeftoversRow { Item: { } item } row) return;
        ShowDetail(row);
        if (_vm is null || _explaining) return;
        _explaining = true;
        _ = ExplainAsync(item);
    }

    private async Task ExplainAsync(LeftoverItemModel item)
    {
        try
        {
            await _vm!.ExplainAsync(item);
            if (Items.ItemsSource is List<LeftoversRow> rows)
                foreach (var r in rows.Where(r => r.Item?.CandidateId == item.CandidateId)) r.RaiseEvidence();
            if (Items.SelectedItem is LeftoversRow { Item: { } current } row && current.CandidateId == item.CandidateId)
                ShowDetail(row);
        }
        finally
        {
            _explaining = false;
        }
    }

    private void OnItemCheck(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { DataContext: LeftoversRow { Item: { } item } row } box) return;
        var on = box.IsChecked == true;
        _vm?.SetChecked(item, on);
        row.Checked = on;
        RefreshGroupRows(item.GroupName);
        if (_vm is not null)
        {
            UpdateCounts(_vm);
            UpdateMove(_vm);
        }
        // The row's spoken name carries its tick state.
        if (Items.ContainerFromItem(row) is ListViewItem container) AutomationProperties.SetName(container, row.ToString());
    }

    /// <summary>
    /// Names each row container for screen readers (otherwise it reads the class name): group and count, or item,
    /// rating and tick state.
    /// </summary>
    private void OnContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
    {
        if (args.InRecycleQueue) return;
        if (args.Item is LeftoversRow row) AutomationProperties.SetName(args.ItemContainer, row.ToString());
    }

    /// <summary>Updates the one group header a tick belongs to, without rebuilding 2,000 rows.</summary>
    private void RefreshGroupRows(string groupName)
    {
        if (Items.ItemsSource is not List<LeftoversRow> rows) return;
        foreach (var row in rows)
        {
            if (row.Group?.Name == groupName) row.RaiseGroup();
        }
    }

    /// <summary>Group boxes tick Safe items only; Likely and user-data items need their own tick.</summary>
    private void OnGroupCheck(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { DataContext: LeftoversRow { Group: { } group } }) return;
        _vm?.ToggleGroup(group);
        Refresh();
    }

    private void OnToggleGroup(object sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: LeftoversRow { Group: { } group } })
        {
            group.Expanded = !group.Expanded;
            Refresh();
        }
    }

    private void OnExpandAll(object sender, RoutedEventArgs e)
    {
        if (_vm is null) return;
        var expand = _vm.Groups.Any(g => !g.Expanded);
        foreach (var group in _vm.Groups) group.Expanded = expand;
        Refresh();
    }

    private void OnToggleWeak(object sender, RoutedEventArgs e)
    {
        if (_vm is null) return;
        _vm.ShowWeak = !_vm.ShowWeak;
        if (!_vm.ShowWeak)
            foreach (var item in _vm.Items.Where(i => i.IsWeak && i.Checked)) item.Checked = false;
    }

    private void OnDeleteAfter(object sender, RoutedEventArgs e)
    {
        if (_vm is null) return;
        _vm.DeleteAfter = DeleteAfterBox.IsChecked == true;
        UpdateMove(_vm);
    }

    private async void OnMove(object sender, RoutedEventArgs e)
    {
        if (_vm is null) return;
        MoveButton.IsEnabled = false;
        await _vm.MoveAsync(_request?.RestorePoint ?? RestorePoint.HighRisk);
    }

    private async void OnUndoAll(object sender, RoutedEventArgs e)
    {
        if (_vm is null) return;
        if (_vm.UndoOpensHistory)
        {
            // After a delete step, or when this page's broker has ended: History shows what can still be put back.
            MainWindow.Instance.Navigate("history");
            return;
        }
        UndoAllButton.IsEnabled = false;
        try { await _vm.UndoAllAsync(); }
        finally { UndoAllButton.IsEnabled = true; }
    }

    private async void OnRetryHeld(object sender, RoutedEventArgs e)
    {
        if (_vm is null) return;
        RetryHeldButton.IsEnabled = false;
        try { await _vm.RetryHeldAsync(); }
        finally { RetryHeldButton.IsEnabled = true; }
    }

    private void OnDone(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("programs");

    private void OnSkip(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("programs");

    /// <summary>The sample view and the stopgap path have no broker; every RPC is a refusal.</summary>
    private sealed class OfflineBroker : ILeftoversBroker
    {
        public event Action<ConsentShown>? ConsentShown
        {
            add { }
            remove { }
        }

        public event Action<BaselineChanged>? BaselineChanged
        {
            add { }
            remove { }
        }

        public bool IsLive => false;

        public Task<ScanResult> ScanSessionAsync(string sessionId, bool forced, IProgress<Progress>? progress, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");

        public Task<ScanResult> ScanStoredAsync(string programId, IProgress<Progress>? progress, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");

        public Task<CandidatesPage> CandidatesAsync(string scanId, uint offset, int limit, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");

        public Task<Explanation> ExplainAsync(string scanId, string candidateId, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");

        public Task<PlanCreated> CreatePlanAsync(string scanId, IReadOnlyList<string> selected, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");

        public Task<RpcExecResult> ExecuteAsync(string planId, RestorePoint restorePoint, IProgress<Progress>? progress, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");

        public Task<RpcExecResult> ExecuteThenDeleteAsync(string planId, RestorePoint restorePoint, IProgress<Progress>? progress, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");

        public Task<RpcUndoResult> UndoAsync(string session, IProgress<Progress>? progress, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");

        public Task<OutcomeResult> RetryHeldAsync(string session, CancellationToken ct) =>
            throw new BrokerLinkException("The administrator part is not connected.");
    }
}
