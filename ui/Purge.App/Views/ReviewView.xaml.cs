using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Purge.App.Shell;
using Purge.Client.Cli;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>S3 on sample data (Firefox). The quarantine button opens the security prompt preview; nothing moves.</summary>
public sealed partial class ReviewView : UserControl
{
    private static readonly Brush Explicit = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0x2E, 0x9E, 0x44));
    private static readonly Brush Warning = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0xD1, 0x34, 0x38));
    private static readonly Brush Note = new SolidColorBrush(Windows.UI.Color.FromArgb(255, 0x8A, 0x8A, 0x8A));

    private const string Weak = "Weak matches";
    private List<LeftoverRow> _all = Program.Engine.IsLive ? [] : Sample();
    private bool _showWeak;
    private bool _promptOpen;

    public ReviewView()
    {
        InitializeComponent();
        AppTile.Background = ProgramRow.TileFor("Mozilla");
        ApplyPreset(Settings.Preset);
        Refresh();
        if (Program.Engine.IsLive)
        {
            AppInitial.Text = "?";
            TitleText.Text = "Leftovers";
            SubtitleText.Text = "No scan yet";
            ShowInfo(InfoBarSeverity.Informational, "Nothing scanned yet.",
                "In Programs, pick a program and choose Uninstall (runs its uninstaller, then scans) or Force remove (scans only).");
        }
        else
            Items.SelectedItem = _all.First(r => r.IsUserData);
        // The page is cached by the shell; pick up a preset changed in Settings since it was last shown.
        Loaded += (_, _) =>
        {
            _askRetries = 0;
            DispatcherQueue.TryEnqueue(PlaceAsk);
            if (_appliedPreset == Settings.Preset && _appliedUserData == Settings.PreSelectUserData) return;
            ApplyPreset(Settings.Preset);
            UpdateCounts();
        };
    }

    private SafetyPreset _appliedPreset;
    private bool _appliedUserData;

    private IEnumerable<LeftoverRow> Candidates => _all.Where(r => !r.IsGroup && (_showWeak || r.GroupName != Weak));

    private void Refresh()
    {
        var visible = new List<LeftoverRow>();
        var collapsed = new HashSet<string>(_all.Where(r => r.IsGroup && !r.Expanded).Select(r => r.GroupName));
        foreach (var r in _all)
        {
            if (r.GroupName == Weak && !_showWeak) continue;
            if (!r.IsGroup && collapsed.Contains(r.GroupName)) continue;
            visible.Add(r);
        }
        var selected = Items.SelectedItem;
        Items.ItemsSource = visible;
        if (selected is LeftoverRow s && visible.Contains(s)) Items.SelectedItem = s;
        UpdateCounts();
    }

    private void UpdateCounts()
    {
        foreach (var g in _all.Where(r => r.IsGroup))
        {
            var items = _all.Where(r => !r.IsGroup && r.GroupName == g.GroupName).ToList();
            var selectable = items.Where(i => i.Selectable).ToList();
            g.CountText = items.Count.ToString(CultureInfo.CurrentCulture);
            g.GroupChecked = selectable.Count == 0 ? false
                : selectable.All(i => i.Checked) ? true
                : selectable.Any(i => i.Checked) ? null : false;
            var ticked = items.Count(i => i.Checked);
            g.GroupBarWidth = items.Count == 0 ? 0 : 120.0 * ticked / items.Count;
            g.GroupBarTip = $"{ticked} of {items.Count} selected";
            var bytes = items.Sum(i => i.SizeBytes);
            g.GroupSizeText = bytes > 0 ? ProgramRow.FormatSize(bytes) : $"{ticked} of {items.Count}";
        }

        var cands = Candidates.ToList();
        var safeN = cands.Count(c => c.Band == Band.Safe);
        var likelyN = cands.Count(c => c.Band is Band.Likely or Band.Weak);
        var protN = cands.Count(c => c.Band == Band.Protected);
        SafePill.Text = $"Safe {safeN} · {ProgramRow.FormatSize(cands.Where(c => c.Band == Band.Safe).Sum(c => c.SizeBytes))}";
        LikelyPill.Text = $"Likely {likelyN} · {ProgramRow.FormatSize(cands.Where(c => c.Band is Band.Likely or Band.Weak).Sum(c => c.SizeBytes))}";
        ProtectedPill.Text = $"Protected {protN}";
        BarSafe.Width = new GridLength(Math.Max(safeN, 0.01), GridUnitType.Star);
        BarLikely.Width = new GridLength(Math.Max(likelyN, 0.01), GridUnitType.Star);
        BarProtected.Width = new GridLength(Math.Max(protN, 0.01), GridUnitType.Star);
        var weak = _all.Count(r => !r.IsGroup && r.GroupName == Weak);
        WeakButton.Content = _showWeak ? $"Hide weak matches ({weak})" : $"Show weak matches ({weak})";

        var chosen = cands.Where(c => c.Checked).ToList();
        var selectableCount = cands.Count(c => c.Selectable);
        FooterCount.Text = $"{chosen.Count} of {selectableCount} selected";
        VerdictText.Text = $"{chosen.Count} {(chosen.Count == 1 ? "item" : "items")} · {ProgramRow.FormatSize(chosen.Sum(c => c.SizeBytes))}";
        var parts = new List<string> { ProgramRow.FormatSize(chosen.Sum(c => c.SizeBytes)) };
        AddPart(parts, chosen.Count(c => c.Kind == LeftoverKind.File), "file item", "file items");
        AddPart(parts, chosen.Count(c => c.Kind == LeftoverKind.Registry), "registry item", "registry items");
        AddPart(parts, chosen.Count(c => c.Kind == LeftoverKind.Task), "task or service", "tasks and services");
        FooterDetail.Text = " · " + string.Join(", ", parts);
        MoveText.Text = chosen.Count == 1 ? "Move 1 item to quarantine…" : $"Move {chosen.Count} items to quarantine…";
        MoveButton.IsEnabled = chosen.Count > 0 && !_promptOpen && !_busy;
    }

    private static void AddPart(List<string> parts, int n, string one, string many)
    {
        if (n > 0) parts.Add($"{n} {(n == 1 ? one : many)}");
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Items.SelectedItem is not LeftoverRow { IsGroup: false } row) return;
        DPath.Text = row.Path;
        DSafe.Visibility = Vis(row.Band == Band.Safe);
        DLikely.Visibility = Vis(row.Band == Band.Likely);
        DWeak.Visibility = Vis(row.Band == Band.Weak);
        DProtected.Visibility = Vis(row.Band == Band.Protected);
        DUserData.Visibility = Vis(row.IsUserData);
        DPreselect.Text = row.Band == Band.Protected ? "Never removed"
            : Settings.PreSelects(Settings.Preset, row.Band, row.IsUserData) ? "Pre-selected" : "Not pre-selected";
        _askRetries = 0;
        DispatcherQueue.TryEnqueue(PlaceAsk);
        DEvidence.ItemsSource = row.Evidence ?? Generic(row);
        DContents.Text = row.Contents.Length > 0 ? row.Contents : row.SizeText.Length > 0 ? row.SizeText : "—";
        DIfRemoved.Text = row.Band == Band.Protected
            ? "Purge never removes it"
            : "Moved to quarantine, restorable for 30 days";
        DFoundBy.Text = row.FoundBy.Length > 0 ? row.FoundBy : row.Kind switch
        {
            LeftoverKind.Registry => "Registry scanner · pre-uninstall record",
            LeftoverKind.Task => "Services and tasks scanner",
            _ => "File system scanner",
        };
    }

    // ---- Board 22: inline "Ask" ------------------------------------------------------------------------------

    private ScrollViewer? _listScroller;
    private bool _askRetry;
    private int _askRetries;

    private void RetryAsk(object? sender, object e)
    {
        Items.LayoutUpdated -= RetryAsk;
        _askRetry = false;
        PlaceAsk(); // re-arms itself only if the row is still not there; LayoutUpdated fires per layout pass, not per frame

    }

    private void OnListHostSizeChanged(object sender, SizeChangedEventArgs e) => PlaceAsk();

    /// <summary>Puts the single Ask button on the selected row, or hides it (setting off, no row, row scrolled away).</summary>
    private void PlaceAsk()
    {
        if (!Settings.InlineAssistant || Items.SelectedItem is not LeftoverRow { IsGroup: false } row)
        {
            if (AskButton is not null) AskButton.Visibility = Visibility.Collapsed;
            return;
        }
        if (AskLayer is null)
        {
            FindName(nameof(AskLayer));
            AskTip.Target = AskButton;
        }
        if (_listScroller is null && FindScroller(Items) is { } sv)
        {
            _listScroller = sv;
            sv.ViewChanged += (_, _) => PlaceAsk();
        }
        // By index, and as FrameworkElement: under Native AOT the container comes back typed as ContentControl,
        // not ListViewItem.
        if (Items.SelectedIndex < 0 || Items.ContainerFromIndex(Items.SelectedIndex) is not FrameworkElement item || item.ActualHeight == 0)
        {
            // Row not realized yet (first show): try again once the list has laid out.
            AskButton.Visibility = Visibility.Collapsed;
            if (!_askRetry && _askRetries++ < 5)
            {
                _askRetry = true;
                Items.LayoutUpdated += RetryAsk;
            }
            return;
        }
        var at = item.TransformToVisual(ListHost).TransformPoint(default);
        var top = at.Y + (item.ActualHeight - 28) / 2;
        if (top < 0 || at.Y + item.ActualHeight > ListHost.ActualHeight + 1)
        {
            AskButton.Visibility = Visibility.Collapsed;
            AskTip.IsOpen = false;
            return;
        }
        // Left of the rating chip column (96) and size column (64) of the row template.
        Canvas.SetLeft(AskButton, Math.Max(at.X + 40, at.X + item.ActualWidth - 12 - 64 - 8 - 96 - 8 - 64));
        Canvas.SetTop(AskButton, top);
        AskButton.Visibility = Visibility.Visible;
    }

    private static ScrollViewer? FindScroller(DependencyObject root)
    {
        for (var i = 0; i < VisualTreeHelper.GetChildrenCount(root); i++)
        {
            var child = VisualTreeHelper.GetChild(root, i);
            if (child is ScrollViewer sv) return sv;
            if (FindScroller(child) is { } found) return found;
        }
        return null;
    }

    private void OnAsk(object sender, RoutedEventArgs e)
    {
        if (Items.SelectedItem is not LeftoverRow { IsGroup: false } row) return;
        var name = row.Path.Length > 48 ? "…" + row.Path[^47..] : row.Path;
        AskTip.Title = "Assistant";
        AskTip.Subtitle = name;
        AskQuestion.Text = row.Band == Band.Protected ? "Why can't this be removed?"
            : row.Checked ? "Why is this one selected?" : "Why isn't this one selected?";
        AskAnswer.Text = row.Band switch
        {
            Band.Protected => $"Purge never removes it: {row.Why}. No setting or preset changes that.",
            Band.Weak => $"It only matches by name ({row.Why}). Weak matches are never ticked for you; leave it unless you recognise it.",
            Band.Safe => $"The engine rated it Safe: {row.Why}. If you tick it, it goes to quarantine and can be put back for 30 days.",
            _ when row.IsUserData => $"It holds your data ({(row.Contents.Length > 0 ? row.Contents : row.SizeText)}). The engine rated it Likely: {row.Why}. " +
                                     "User data is never ticked for you; tick it only if you no longer need what is inside.",
            _ => $"The engine rated it Likely, not Safe: {row.Why}. Likely items are left for you to decide; if you tick it, it can be put back for 30 days.",
        };
        AskChecked.Text = row.Evidence is { Count: > 0 } ev ? "Engine checked: " + ev[0].Text : "Engine checked: " + row.Why;
        AskTip.ActionButtonContent = row.Selectable ? (row.Checked ? "Untick it" : "Tick it") : null;
        AskTip.RequestedTheme = MainWindow.Instance.ActualTheme;
        AskTip.IsOpen = true;
    }

    /// <summary>The assistant's only power: change a tick the user can see. Moving still needs the security prompt.</summary>
    private void OnAskAction(TeachingTip sender, object args)
    {
        if (Items.SelectedItem is LeftoverRow { IsGroup: false, Selectable: true } row)
        {
            row.Checked = !row.Checked;
            UpdateCounts();
        }
        sender.IsOpen = false;
    }

    private static List<EvidenceLine> Generic(LeftoverRow row) => row.Band switch
    {
        Band.Protected => [new("○", Note, row.Why), new("●", Explicit, "Kept: protected items are listed for information only")],
        Band.Weak => [new("○", Note, row.Why), new("○", Note, "Matches by name only, so it is never ticked for you")],
        _ => [new("●", Explicit, row.Why), new("◐", Explicit, "No other installed program refers to it · ownership index")],
    };

    private static Visibility Vis(bool on) => on ? Visibility.Visible : Visibility.Collapsed;

    private void OnItemCheck(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox { DataContext: LeftoverRow row } box)
        {
            row.Checked = box.IsChecked == true;
            UpdateCounts();
        }
    }

    /// <summary>Group checkboxes toggle Safe items only; Likely and user-data items need their own tick (§9.4).</summary>
    private void OnGroupCheck(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox { DataContext: LeftoverRow group }) return;
        var safe = _all.Where(r => !r.IsGroup && r.GroupName == group.GroupName && r.Band == Band.Safe).ToList();
        var on = !safe.All(r => r.Checked);
        foreach (var r in safe) r.Checked = on;
        if (!on)
            foreach (var r in _all.Where(r => !r.IsGroup && r.GroupName == group.GroupName)) r.Checked = false;
        UpdateCounts();
    }

    private void OnToggleGroup(object sender, RoutedEventArgs e)
    {
        if (sender is Button { DataContext: LeftoverRow group })
        {
            group.Expanded = !group.Expanded;
            Refresh();
        }
    }

    private void OnExpandAll(object sender, RoutedEventArgs e)
    {
        var expand = _all.Where(r => r.IsGroup).Any(g => !g.Expanded);
        foreach (var g in _all.Where(r => r.IsGroup)) g.Expanded = expand;
        ExpandButton.Content = expand ? "Collapse all" : "Expand all";
        Refresh();
    }

    private void OnToggleWeak(object sender, RoutedEventArgs e)
    {
        _showWeak = !_showWeak;
        if (!_showWeak)
            foreach (var r in _all.Where(r => r.GroupName == Weak)) r.Checked = false;
        Refresh();
    }

    private void OnSelectPreset(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuFlyoutItem { Tag: string tag, Text: string text }) return;
        ApplyPreset(tag switch { "likely" => SafetyPreset.Thorough, "none" => SafetyPreset.Cautious, _ => SafetyPreset.Balanced });
        SelectButton.Content = "Select: " + text;
        UpdateCounts();
    }

    /// <summary>
    /// Ticks what a preset pre-selects (board 17). Presets change only the ticks in this list: user data and
    /// Protected items are never ticked by any preset (S19), and the engine's guard lists are not involved.
    /// </summary>
    private void ApplyPreset(SafetyPreset preset)
    {
        _appliedPreset = preset;
        _appliedUserData = Settings.PreSelectUserData;
        foreach (var r in _all.Where(c => !c.IsGroup && c.Selectable))
            r.Checked = Settings.PreSelects(preset, r.Band, r.IsUserData);
        SelectButton.Content = "Select: " + preset switch
        {
            SafetyPreset.Cautious => "Nothing",
            SafetyPreset.Thorough => "Safe and Likely",
            _ => "Safe only",
        };
    }

    private void OnSkip(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("programs");

    private void OnSample(object sender, RoutedEventArgs e) { }

    private async void OnMove(object sender, RoutedEventArgs e)
    {
        var chosen = Candidates.Where(c => c.Checked).ToList();
        if (chosen.Count == 0) return;
        if (Program.Engine.IsLive)
        {
            await MoveLiveAsync(chosen);
            return;
        }
        _promptOpen = true;
        UpdateCounts();
        var waiting = ShowInfo(InfoBarSeverity.Informational, "Confirm in the Purge security prompt.", "Nothing has been moved yet.");

        var summary = new ConsentSummary(
            "Mozilla Firefox",
            chosen.Select(c => new ConsentItem(c.Path, c.Kind, c.Band, c.SizeText, c.SizeBytes, c.IsUserData)).ToList(),
            DateTime.Today.AddDays(30));
        var result = await ConsentPrompt.ShowAsync(MainWindow.Instance.Hwnd, summary);

        InfoBarHost.Children.Remove(waiting);
        _promptOpen = false;
        UpdateCounts();
        if (result)
            ShowInfo(InfoBarSeverity.Success, "Confirmed in the security prompt.",
                "This preview isn't connected to the engine, so nothing was moved.");
    }

    // ---- The engine (CliEngineClient) -------------------------------------------------------------------------

    private LeftoverPlan? _plan;
    private bool _busy;

    /// <summary>
    /// Scans a program (after running its uninstaller for <see cref="ScanKind.UninstallThenScan"/>) and shows the
    /// engine's plan: its bands and the engine's own preselection.
    /// </summary>
    public async Task ScanAsync(string programId, string name, ScanKind kind)
    {
        if (_busy)
        {
            ShowInfo(InfoBarSeverity.Warning, "Purge is still busy.", "Wait for the running scan or removal to finish.");
            return;
        }
        _busy = true;
        _plan = null;
        _all = [];
        Refresh();
        AppTile.Background = ProgramRow.TileFor(name);
        AppInitial.Text = name.Length > 0 ? name[..1].ToUpperInvariant() : "?";
        TitleText.Text = $"Leftovers of {name}";
        SubtitleText.Text = kind == ScanKind.UninstallThenScan ? "Uninstalling, then scanning…" : "Scanning without an uninstaller…";
        using var cts = new CancellationTokenSource();
        var bar = ShowInfo(InfoBarSeverity.Informational, "", "");
        bar.IsClosable = false;
        var cancel = new Button { Content = "Cancel" };
        cancel.Click += (_, _) => { cts.Cancel(); cancel.IsEnabled = false; cancel.Content = "Stopping…"; };
        bar.ActionButton = cancel;
        using var activity = new EngineActivity(bar, "Starting the engine");
        try
        {
            var plan = await Program.Engine.ScanAsync(programId, name, kind, activity.Progress, cts.Token);
            activity.Dispose();
            LoadPlan(plan);
            var seconds = activity.Elapsed.TotalSeconds.ToString("F0", CultureInfo.CurrentCulture);
            SubtitleText.Text = (kind == ScanKind.UninstallThenScan ? "Uninstalled and scanned" : "Scanned without an uninstaller")
                                + $" in {seconds} s · restorable for 30 days once moved";
            var ticked = _all.Count(r => r.Checked);
            ShowInfo(plan.Warnings.Count > 0 ? InfoBarSeverity.Warning : InfoBarSeverity.Success,
                $"Found {plan.Items.Count} {(plan.Items.Count == 1 ? "item" : "items")}; the engine ticked {ticked}.",
                plan.Warnings.Count > 0 ? "Engine warnings: " + string.Join(" · ", plan.Warnings.Take(4)) : "Review the list, then move what you want to quarantine.");
        }
        catch (OperationCanceledException)
        {
            SubtitleText.Text = "Cancelled";
            ShowInfo(InfoBarSeverity.Warning, $"Cancelled during \"{activity.StepName}\".",
                "The engine was stopped. If the uninstaller had started, it may have finished part of its work.");
        }
        catch (Exception ex)
        {
            SubtitleText.Text = $"The scan did not finish (step: {activity.StepName})";
            ShowError(ex);
        }
        finally
        {
            _busy = false;
            UpdateCounts();
        }
        if (kind == ScanKind.UninstallThenScan) _ = MainWindow.Instance.Programs.ReloadAsync();
    }

    private static string GroupOf(LeftoverItem i) =>
        i.Band == LeftoverBand.Weak ? Weak
        : i.Category == "Association" ? "File associations & protocols"
        : i.Category == "ShellCom" ? "Shell & COM"
        : i.IsFile ? "Files & folders"
        : i.IsRegistry ? "Registry"
        : "Services, tasks & other";

    private static readonly string[] GroupOrder =
        ["Files & folders", "Registry", "File associations & protocols", "Shell & COM", "Services, tasks & other", Weak];

    private void LoadPlan(LeftoverPlan plan)
    {
        _plan = plan;
        var rows = new List<LeftoverRow>();
        foreach (var group in GroupOrder)
        {
            var items = plan.Items.Where(i => GroupOf(i) == group).ToList();
            if (items.Count == 0) continue;
            rows.Add(LeftoverRow.Header(group));
            foreach (var i in items)
            {
                var band = !i.Selectable ? Band.Protected : i.Band switch
                {
                    LeftoverBand.Safe => Band.Safe,
                    LeftoverBand.Likely => Band.Likely,
                    _ => Band.Weak,
                };
                var why = i.Explanation.Length > 0 ? i.Explanation : i.Category;
                if (i.Action == "RemovePackage") why += " · package removal is not in this build";
                var kind = i.IsFile ? LeftoverKind.File : i.IsRegistry ? LeftoverKind.Registry : LeftoverKind.Task;
                rows.Add(new LeftoverRow(group, i.Display, why, band,
                    i.SizeBytes is { } b ? ProgramRow.FormatSize(b) : "", i.SizeBytes ?? 0, kind)
                {
                    Id = i.Id,
                    IsUserData = i.IsUserData,
                    FoundBy = $"{i.Scanner} · {i.Category} · {i.Action} · {i.Evidence} evidence",
                    Checked = i.Selectable && i.Preselected,
                });
            }
        }
        _all = rows;
        // Weak matches are shown when the engine found any: a real plan is short enough to see them all.
        _showWeak = rows.Any(r => r.GroupName == Weak);
        _appliedPreset = Settings.Preset;
        _appliedUserData = Settings.PreSelectUserData;
        SelectButton.Content = "Select: as the engine ticked";
        Refresh();
        Items.SelectedItem = rows.FirstOrDefault(r => !r.IsGroup);
    }

    private async Task MoveLiveAsync(List<LeftoverRow> chosen)
    {
        if (_plan is not { } plan || _busy || _promptOpen) return;
        _promptOpen = true;
        UpdateCounts();
        var summary = new ConsentSummary(
            plan.ProgramName,
            chosen.Select(c => new ConsentItem(c.Path, c.Kind, c.Band, c.SizeText, c.SizeBytes, c.IsUserData)).ToList(),
            DateTime.Today.AddDays(30));
        bool ok;
        try { ok = await ConsentPrompt.ShowAsync(MainWindow.Instance.Hwnd, summary); }
        finally { _promptOpen = false; }
        if (!ok)
        {
            UpdateCounts();
            return;
        }
        _busy = true;
        MoveButton.IsEnabled = false;
        using var cts = new CancellationTokenSource();
        var bar = ShowInfo(InfoBarSeverity.Informational, "", "");
        bar.IsClosable = false;
        // Stopping a move ends the engine mid-run; its journal then offers Resume or Roll back.
        var stop = new Button { Content = "Stop" };
        stop.Click += (_, _) => { cts.Cancel(); stop.IsEnabled = false; stop.Content = "Stopping…"; };
        bar.ActionButton = stop;
        using var activity = new EngineActivity(bar, $"Moving {chosen.Count} {(chosen.Count == 1 ? "item" : "items")} to quarantine");
        try
        {
            var result = await Program.Engine.ExecAsync(plan, chosen.Select(c => c.Id).ToList(), activity.Progress, cts.Token);
            activity.Dispose();
            ShowExecResult(result, chosen.Count);
            var finished = result.Items.Where(i => i.Complete).Select(i => i.Id).ToHashSet(StringComparer.Ordinal);
            _all = _all.Where(r => r.IsGroup || !finished.Contains(r.Id)).ToList();
            _all = _all.Where(r => !r.IsGroup || _all.Any(i => !i.IsGroup && i.GroupName == r.GroupName)).ToList();
            Refresh();
        }
        catch (EngineException ex) when (ex.NeedsRecovery)
        {
            InfoBarHost.Children.Clear();
            InfoBarHost.Children.Add(RecoveryBar.Create(ex.Message, () => { }));
        }
        catch (OperationCanceledException)
        {
            InfoBarHost.Children.Clear();
            InfoBarHost.Children.Add(RecoveryBar.Create(
                $"The move was stopped after {activity.Elapsed.TotalSeconds:F0} s. Resume it to finish, or roll it back to put everything back.",
                () => { }));
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
        finally
        {
            _busy = false;
            UpdateCounts();
        }
    }

    private void ShowExecResult(ExecResult r, int asked)
    {
        var moved = r.Done + r.Vanished;
        var parts = new List<string> { $"Session {r.SessionId} ({r.State})" };
        if (r.Skipped > 0) parts.Add($"{r.Skipped} skipped");
        if (r.HeldRetry > 0) parts.Add($"{r.HeldRetry} in use, left for a later run");
        if (r.PendingReboot > 0) parts.Add($"{r.PendingReboot} go at the next restart");
        if (r.Failed > 0) parts.Add($"{r.Failed} failed");
        if (r.ExitCode == ExitCodes.Unrecorded) parts.Add(ExitCodes.Describe(ExitCodes.Unrecorded, ""));
        var notDone = r.Items.Where(i => !i.Complete).Take(4)
            .Select(i => $"{i.Display} ({i.Outcome}{(i.Detail.Length > 0 ? ": " + i.Detail : "")})").ToList();
        if (notDone.Count > 0) parts.Add("Not done: " + string.Join("; ", notDone));
        parts.Add("Everything moved can be put back from the Quarantine vault.");
        var bar = ShowInfo(r.ExitCode == ExitCodes.Ok ? InfoBarSeverity.Success : InfoBarSeverity.Warning,
            $"Moved {moved} of {asked} {(asked == 1 ? "item" : "items")} to quarantine.", string.Join(" · ", parts));
        var open = new Button { Content = "Open the vault" };
        open.Click += (_, _) => MainWindow.Instance.Navigate("vault");
        bar.ActionButton = open;
    }

    private void ShowError(Exception ex)
    {
        var bar = ShowInfo(InfoBarSeverity.Error, ex is EngineException ? "The engine refused or failed." : "Something went wrong.", ex.Message);
        if (ex is EngineException { Stderr.Length: > 0 } ee) ToolTipService.SetToolTip(bar, ee.Stderr);
    }

    private InfoBar ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        InfoBarHost.Children.Clear();
        var bar = new InfoBar { Severity = severity, Title = title, Message = message, IsOpen = true, IsClosable = true };
        // Pin to the window theme: code-made InfoBars otherwise take the warning/info fill from the app theme
        // (Windows setting), not from Settings → Appearance.
        bar.RequestedTheme = MainWindow.Instance.ActualTheme;
        bar.Closed += (s, _) => InfoBarHost.Children.Remove(s);
        InfoBarHost.Children.Add(bar);
        return bar;
    }

    internal static List<LeftoverRow> Sample()
    {
        const string F = "Files & folders", R = "Registry", A = "File associations & protocols", C = "Shell & COM", S = "Services & tasks";
        return
        [
            LeftoverRow.Header(F),
            LeftoverRow.Item(F, @"C:\Users\tester\AppData\Local\Mozilla", "App cache · only Firefox data inside · vendor folder", Band.Safe, "2.6 MB", 2_726_297),
            LeftoverRow.Item(F, @"C:\ProgramData\Mozilla-1de4eec8-1241-4177-a864-e594e8d1fb38", "Update data · Firefox's registry pointed here before uninstall", Band.Safe, "96 KB", 98_304),
            LeftoverRow.Item(F, @"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Firefox Private Browsing.lnk", @"Shortcut to C:\Program Files\Mozilla Firefox\private_browsing.exe (gone)", Band.Safe, "2 KB", 2_048),
            new LeftoverRow(F, @"C:\Users\tester\AppData\Roaming\Mozilla", "Profile folder · holds bookmarks and logins", Band.Likely, "2.1 MB", 2_202_009)
            {
                IsUserData = true,
                Contents = "37 files, 2.1 MB",
                FoundBy = "Vendor folder scanner · pre-uninstall record",
                Evidence =
                [
                    new("●", Explicit, @"Firefox's settings pointed to Mozilla\Firefox\Profiles before uninstall · recorded before uninstall"),
                    new("◐", Explicit, "Named Mozilla, the publisher on Firefox's uninstall entry and signature"),
                    new("◐", Explicit, "No other installed program refers to it · ownership index"),
                    new("⚠", Warning, "Holds your data: bookmarks, history, saved logins (places.sqlite, logins.json)"),
                    new("○", Note, "Vendor folder: Thunderbird would share it. It isn't installed."),
                ],
            },
            LeftoverRow.Item(F, @"C:\Windows\Prefetch", "Windows folder · never touched", Band.Protected),

            LeftoverRow.Header(R),
            LeftoverRow.Item(R, @"HKCU\Software\Mozilla\Firefox", @"Values pointed to C:\Program Files\Mozilla Firefox before uninstall", Band.Safe, "12 values", 0, LeftoverKind.Registry),
            LeftoverRow.Item(R, @"HKLM\Software\Mozilla\Firefox", @"Values pointed to C:\Program Files\Mozilla Firefox before uninstall", Band.Safe, "4 values", 0, LeftoverKind.Registry),
            LeftoverRow.Item(R, @"HKLM\Software\Microsoft\MediaPlayer\ShimInclusionList\firefox.exe", "Keyed by firefox.exe · not on clean Windows 11", Band.Likely, "1 key", 0, LeftoverKind.Registry),

            LeftoverRow.Header(A),
            LeftoverRow.Item(A, @"Classes\.htm, .html, .pdf, .svg, .webp … \OpenWithProgids → FirefoxHTML-308046B0AF4A39CB", "Only Firefox's value is removed; the extension keys stay", Band.Safe, "7 values", 0, LeftoverKind.Registry),
            LeftoverRow.Item(A, @"HKLM\Software\Classes\FirefoxHTML-308046B0AF4A39CB", "Firefox's ProgID · recorded before uninstall", Band.Safe, "6 keys", 0, LeftoverKind.Registry),
            LeftoverRow.Item(A, @"HKLM\Software\Classes\.pdf", "Present on clean Windows 11 · Edge uses it", Band.Protected, "", 0, LeftoverKind.Registry),

            LeftoverRow.Header(C),
            LeftoverRow.Item(C, @"HKLM\Software\Classes\CLSID\{1814CEEB-49E2-407F-AF99-FA755A7D2607}", "COM class · server was notificationserver.dll in Firefox's folder", Band.Likely, "3 keys", 0, LeftoverKind.Registry),

            LeftoverRow.Header(S),
            LeftoverRow.Item(S, "Task: Firefox Default Browser Agent 308046B0AF4A39CB", "Action ran default-browser-agent.exe from Firefox's folder", Band.Safe, "", 0, LeftoverKind.Task),
            LeftoverRow.Item(S, "Service: Mozilla Maintenance Service", "Left by the uninstaller · could serve other Mozilla apps", Band.Likely, "", 0, LeftoverKind.Task),

            LeftoverRow.Header(Weak),
            LeftoverRow.Item(Weak, @"C:\Users\tester\AppData\Local\Temp\firefox-crash-reports", "Name contains \"firefox\" · nothing else links it", Band.Weak, "640 KB", 655_360),
            LeftoverRow.Item(Weak, @"HKCU\Software\Classes\firefox-bridge", "Name contains \"firefox\" · no values point to Firefox", Band.Weak, "1 key", 0, LeftoverKind.Registry),
        ];
    }
}
