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
        InitFilters();
        if (Alpha.On)
        {
            MoveButton.IsEnabled = false;
            ToolTipService.SetToolTip(MoveHost, Alpha.Tooltip);
        }
        ApplyPreset(Settings.Preset);
        Refresh();
        if (Program.Engine.IsLive)
        {
            AppInitial.Text = "?";
            TitleText.Text = "Leftovers";
            SubtitleText.Text = "No scan yet";
            ShowInfo(InfoBarSeverity.Informational, "Nothing scanned yet.",
                "In Programs, pick a program and choose Scan leftovers (records it and scans while it is still installed), " +
                "or use Saved fingerprints to scan one you recorded before uninstalling it yourself.");
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
        // A group stays when any of its items passes the filters, even while it is collapsed.
        var shownGroups = new HashSet<string>(_all.Where(r => !r.IsGroup && Matches(r)).Select(r => r.GroupName));
        int shown = 0, total = 0;
        foreach (var r in _all)
        {
            if (r.GroupName == Weak && !_showWeak) continue;
            if (r.IsGroup)
            {
                if (shownGroups.Contains(r.GroupName)) visible.Add(r);
                continue;
            }
            total++;
            if (!Matches(r)) continue;
            shown++;
            if (collapsed.Contains(r.GroupName)) continue;
            visible.Add(r);
        }
        FilterCount.Text = shown == total ? $"{total} {(total == 1 ? "item" : "items")}" : $"Showing {shown} of {total}";
        var selected = Items.SelectedItem;
        Items.ItemsSource = visible;
        if (selected is LeftoverRow s && visible.Contains(s)) Items.SelectedItem = s;
        UpdateCounts();
    }

    // ---- Filters (alpha) ---------------------------------------------------------------------------------------

    private const string AllTypes = "All types", AllBands = "All bands", AllPicks = "Any selection";
    private static readonly string[] BandChoices = [AllBands, "Safe", "Likely", "Weak", "Blocked / kept"];
    private static readonly string[] PickChoices = [AllPicks, "Engine ticked", "Engine did not tick", "Ticked now", "Not ticked now"];
    private bool _fillingFilters;

    private void InitFilters()
    {
        _fillingFilters = true;
        TypeFilter.ItemsSource = new List<string> { AllTypes };
        TypeFilter.SelectedIndex = 0;
        BandFilter.ItemsSource = BandChoices.ToList();
        BandFilter.SelectedIndex = 0;
        PickFilter.ItemsSource = PickChoices.ToList();
        PickFilter.SelectedIndex = 0;
        _fillingFilters = false;
    }

    /// <summary>The type filter lists the groups present, with their counts.</summary>
    private void FillTypeFilter()
    {
        _fillingFilters = true;
        var names = new List<string> { AllTypes };
        names.AddRange(_all.Where(r => r.IsGroup).Select(g => g.GroupName));
        TypeFilter.ItemsSource = names;
        TypeFilter.SelectedIndex = 0;
        BandFilter.SelectedIndex = 0;
        PickFilter.SelectedIndex = 0;
        FilterText.Text = "";
        _fillingFilters = false;
    }

    private bool Matches(LeftoverRow r)
    {
        if (TypeFilter.SelectedItem is string type && type != AllTypes && r.GroupName != type) return false;
        switch (BandFilter.SelectedIndex)
        {
            case 1 when r.Band != Band.Safe:
            case 2 when r.Band != Band.Likely:
            case 3 when r.Band != Band.Weak:
            case 4 when r.Band != Band.Protected:
                return false;
        }
        switch (PickFilter.SelectedIndex)
        {
            case 1 when !r.EngineTicked:
            case 2 when r.EngineTicked:
            case 3 when !r.Checked:
            case 4 when r.Checked:
                return false;
        }
        var text = FilterText.Text.Trim();
        if (text.Length == 0) return true;
        return r.Path.Contains(text, StringComparison.OrdinalIgnoreCase)
               || r.Why.Contains(text, StringComparison.OrdinalIgnoreCase)
               || r.FoundBy.Contains(text, StringComparison.OrdinalIgnoreCase)
               || (r.Source?.ObjectNote?.Name.Contains(text, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private void OnFilterChanged(object sender, object e)
    {
        if (_fillingFilters) return;
        Refresh();
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
        MoveButton.IsEnabled = !Alpha.On && chosen.Count > 0 && !_promptOpen && !_busy;
        ExportButton.IsEnabled = _plan is not null && chosen.Count > 0 && !_busy;
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
        ShowEngineDetails(row.Source);
    }

    /// <summary>The alpha's details of an engine item: every fact the scan document carries about it.</summary>
    private void ShowEngineDetails(LeftoverItem? i)
    {
        var on = i is not null;
        DFactsTitle.Visibility = DFacts.Visibility = DTarget.Visibility = Vis(on);
        OpenLocationButton.IsEnabled = i is { IsFile: true };
        CopyButton.IsEnabled = on;
        if (i is null) return;
        if (i.Band == LeftoverBand.Blocked || !i.Selectable)
            DIfRemoved.Text = i.IsUninstallNotice ? $"Notice only: consider uninstalling {i.SuggestUninstall} yourself; Purge removes nothing here"
                : i.Action == "RemovePackage" ? "Package removal cannot be undone; not offered in this build"
                : i.Action == "ReportOnly" ? "Shown for information only" : "Purge never removes it";
        else
            DIfRemoved.Text = (i.Action switch
            {
                "Quarantine" => "Moved to quarantine",
                "DeleteKey" when i.TargetType == "Service" => "Service deleted after its definition is stored",
                "DeleteKey" when i.TargetType == "Task" => "Task deleted after its XML is stored",
                "DeleteKey" when i.TargetType == "FirewallRule" => "Rule deleted after it is stored",
                "DeleteKey" => "Key deleted after a backup",
                "DeleteValue" => "Value deleted after a backup",
                "EditSegment" => "One entry removed from the value",
                "RemoveDirIfEmpty" => "Removed only if empty by then",
                _ => i.Action,
            }) + $" · undo: {i.Reversibility} (not in the alpha)";
        var lines = new List<string>
        {
            $"Type: {i.TargetType} · group {EngineDocs.Describe(i.Type)}",
            $"Action: {i.Action} · category {i.Category}",
            $"Band: {i.Band} · score {i.Score} · {(i.Preselected ? "ticked by the engine" : "not ticked by the engine")}",
            $"Harm if wrong: {i.Harm} · reversibility {i.Reversibility}",
            $"Scanners: {string.Join(", ", i.Scanners)}",
        };
        if (i.Owner.Length > 0) lines.Add($"Attributed to: {i.Owner}");
        if (i.SizeBytes is { } b) lines.Add($"Size: {ProgramRow.FormatSize(b)} ({b:N0} bytes)");
        if (i.ChildCount is { } n) lines.Add($"Inside: {n} files or values");
        if (i.Children > 0) lines.Add($"Nested candidates: {i.Children}");
        if (i.ObjectWhy.Length > 0) lines.Add($"Why it is the app's object: {WhyText(i.ObjectWhy)}");
        if (i.ObjectNote is { } note)
        {
            if (note.Name.Length > 0 && i.TargetType != "Task") lines.Add($"Name: {note.Name}");
            if (note.Program.Length > 0) lines.Add($"Program: {note.Program}");
            if (note.Details.Length > 0) lines.Add($"Recorded: {note.Details}");
        }
        if (i.ObjectKind.Length > 0) lines.Add($"Bound to the scan's {i.ObjectKind} digest");
        if (i.Blockers.Count > 0) lines.Add("Blockers: " + string.Join("; ", i.Blockers));
        lines.Add($"Id: {i.Id}");
        DFacts.Text = string.Join(Environment.NewLine, lines);
        DTarget.Text = i.TargetJson;
    }

    private static string WhyText(string why) => why switch
    {
        "program_in_root" => "its program lies in the app's folder (program_in_root)",
        "program_is_app_exe" => "its program is one of the app's executables (program_is_app_exe)",
        "msi_service_row" => "the app's MSI package installs it (msi_service_row)",
        "app_com_class" => "every action is one of the app's COM classes (app_com_class)",
        _ => why,
    };

    /// <summary>Evidence and blockers of an engine item as lines of the "why" card.</summary>
    private static List<EvidenceLine> EvidenceLines(LeftoverItem i)
    {
        var lines = new List<EvidenceLine>();
        if (i.Explanation.Length > 0) lines.Add(new("●", i.Band == LeftoverBand.Blocked ? Note : Explicit, i.Explanation));
        foreach (var e in i.EvidenceList)
        {
            var detail = string.Join(" · ", e.Detail.Select(kv => $"{kv.Key}: {kv.Value}"));
            lines.Add(new(e.Negative ? "○" : e.Tier == "A" ? "●" : "◐", e.Negative ? Note : Explicit,
                $"{e.Kind} (tier {e.Tier}, weight {e.Weight}, {e.Scope}) · {e.Source}{(detail.Length > 0 ? " · " + detail : "")}"));
        }
        foreach (var b in i.Blockers) lines.Add(new("⚠", Warning, "Blocker: " + b));
        return lines;
    }

    private void OnOpenLocation(object sender, RoutedEventArgs e)
    {
        if (Items.SelectedItem is not LeftoverRow { Source.IsFile: true } row) return;
        var path = row.Path;
        // Read-only: Explorer opens the folder with the item selected (or the parent when the item is gone).
        var args = File.Exists(path) || Directory.Exists(path) ? $"/select,\"{path}\"" : $"\"{Path.GetDirectoryName(path)}\"";
        try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe", args) { UseShellExecute = false }); }
        catch (Exception ex) { ShowInfo(InfoBarSeverity.Error, "Couldn't open Explorer.", ex.Message); }
    }

    private void OnCopyIdentity(object sender, RoutedEventArgs e)
    {
        if (Items.SelectedItem is not LeftoverRow { Source: { } i }) return;
        var data = new Windows.ApplicationModel.DataTransfer.DataPackage();
        data.SetText(i.TargetJson.Length > 0 ? i.TargetJson : i.Display);
        Windows.ApplicationModel.DataTransfer.Clipboard.SetContent(data);
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
        if (tag == "engine")
        {
            foreach (var r in _all.Where(c => !c.IsGroup && c.Selectable)) r.Checked = r.Source is null ? r.Band == Band.Safe : r.EngineTicked;
            SelectButton.Content = "Select: as the engine ticked";
            Refresh();
            return;
        }
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
        if (chosen.Count == 0 || Alpha.On) return;
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
    public Task ScanAsync(string programId, string name, ScanKind kind)
    {
        if (Alpha.On && kind == ScanKind.UninstallThenScan)
        {
            ShowInfo(InfoBarSeverity.Warning, Alpha.Tooltip, Alpha.Note);
            return Task.CompletedTask;
        }
        return RunScanAsync(name,
            kind == ScanKind.UninstallThenScan ? "Uninstalling, then scanning…" : "Recording, then scanning while it is still installed (forced)…",
            kind == ScanKind.UninstallThenScan ? "Uninstalled and scanned" : "Scanned while installed (forced mode)",
            (progress, ct) => Program.Engine.ScanAsync(programId, name, kind, progress, ct),
            reloadPrograms: kind == ScanKind.UninstallThenScan);
    }

    /// <summary>Scans a saved fingerprint in one of the engine's modes (post, external, forced).</summary>
    public Task ScanFingerprintAsync(SavedFingerprint fp, string mode) =>
        RunScanAsync(fp.Name, $"Scanning the fingerprint of {fp.Recorded:g} ({mode} mode)…", $"Scanned from a saved fingerprint ({mode} mode)",
            (progress, ct) => Program.Engine.ScanFingerprintAsync(fp, mode, progress, ct), reloadPrograms: false);

    /// <summary>
    /// Runs one engine scan with a progress bar (step, elapsed seconds, the engine's last line) and a Cancel button,
    /// then shows the plan with the engine's bands and preselection.
    /// </summary>
    private async Task RunScanAsync(string name, string running, string done,
        Func<IProgress<EngineProgress>, CancellationToken, Task<LeftoverPlan>> scan, bool reloadPrograms)
    {
        if (_busy)
        {
            ShowInfo(InfoBarSeverity.Warning, "Purge is still busy.", "Wait for the running scan to finish.");
            return;
        }
        _busy = true;
        _plan = null;
        _all = [];
        FillTypeFilter();
        Refresh();
        ShowEngineDetails(null);
        AppTile.Background = ProgramRow.TileFor(name);
        AppInitial.Text = name.Length > 0 ? name[..1].ToUpperInvariant() : "?";
        TitleText.Text = $"Leftovers of {name}";
        SubtitleText.Text = running;
        using var cts = new CancellationTokenSource();
        var bar = ShowInfo(InfoBarSeverity.Informational, "", "");
        bar.IsClosable = false;
        var cancel = new Button { Content = "Cancel" };
        cancel.Click += (_, _) => { cts.Cancel(); cancel.IsEnabled = false; cancel.Content = "Stopping…"; };
        bar.ActionButton = cancel;
        using var activity = new EngineActivity(bar, "Starting the engine");
        try
        {
            var plan = await scan(activity.Progress, cts.Token);
            activity.Dispose();
            LoadPlan(plan);
            var seconds = activity.Elapsed.TotalSeconds.ToString("F0", CultureInfo.CurrentCulture);
            SubtitleText.Text = $"{done} in {seconds} s · mode {plan.Mode} · policy {plan.PolicyVersion}"
                                + (Alpha.On ? " · alpha: review only" : " · restorable for 30 days once moved");
            ShowScanResult(plan);
        }
        catch (OperationCanceledException)
        {
            SubtitleText.Text = "Cancelled";
            ShowInfo(InfoBarSeverity.Warning, $"Cancelled during \"{activity.StepName}\" after {activity.Elapsed.TotalSeconds:F0} s.",
                "The engine was stopped. A scan changes nothing, so there is nothing to undo.");
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
        if (reloadPrograms) _ = MainWindow.Instance.Programs.ReloadAsync();
    }

    /// <summary>The result bar, and a second bar when the engine says the scan did not see everything.</summary>
    private void ShowScanResult(LeftoverPlan plan)
    {
        var ticked = _all.Count(r => r.Checked);
        var byBand = plan.Items.GroupBy(i => i.Band).OrderBy(g => g.Key).Select(g => $"{g.Count()} {g.Key}");
        var result = ShowInfo(InfoBarSeverity.Success,
            $"Found {plan.Items.Count} {(plan.Items.Count == 1 ? "item" : "items")}; the engine ticked {ticked}.",
            string.Join(" · ", byBand) + (plan.Absorbed > 0 ? $" · {plan.Absorbed} absorbed by a parent" : "")
            + " · Review the list; Export plan saves it for the CLI.");
        var suggestions = plan.Items.Where(i => i.IsUninstallNotice).Select(i => i.SuggestUninstall)
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        if (suggestions.Count > 0)
            AddInfo(InfoBarSeverity.Informational, "Consider uninstalling: " + string.Join(", ", suggestions),
                "The removed program's installer put it there and left it installed, and no other installer still depends on it. This is a suggestion only: Purge does not remove it; " +
                "uninstall it from Programs (or Windows Settings) if you no longer need it.");
        if (plan.Warnings.Count == 0) return;
        var all = new Button { Content = $"All warnings ({plan.Warnings.Count})" };
        all.Click += async (_, _) => await ShowTextAsync("Engine warnings", string.Join(Environment.NewLine + Environment.NewLine, plan.Warnings));
        var incomplete = plan.IncompleteWarnings;
        if (incomplete.Count == 0)
        {
            result.ActionButton = all;
            return;
        }
        var warn = AddInfo(InfoBarSeverity.Warning, "Parts of the machine were not fully read.",
            $"{incomplete.Count} of the engine's {plan.Warnings.Count} warnings say a walk was cut or something could not be read, so " +
            "some items may be missing or kept from Safe: " + string.Join(" · ", incomplete.Take(3).Select(Short)));
        warn.ActionButton = all;
    }

    private static string Short(string s) => s.Length > 140 ? s[..137] + "…" : s;

    /// <summary>Records a program's fingerprint only, for a later scan after an uninstall outside Purge.</summary>
    public async Task RecordAsync(string programId, string name)
    {
        if (_busy)
        {
            ShowInfo(InfoBarSeverity.Warning, "Purge is still busy.", "Wait for the running scan to finish.");
            return;
        }
        _busy = true;
        using var cts = new CancellationTokenSource();
        var bar = ShowInfo(InfoBarSeverity.Informational, "", "");
        bar.IsClosable = false;
        var cancel = new Button { Content = "Cancel" };
        cancel.Click += (_, _) => { cts.Cancel(); cancel.IsEnabled = false; };
        bar.ActionButton = cancel;
        using var activity = new EngineActivity(bar, $"Recording {name}");
        try
        {
            var fp = await Program.Engine.HarvestAsync(programId, name, activity.Progress, cts.Token);
            activity.Dispose();
            ShowInfo(InfoBarSeverity.Success, $"Recorded {name} in {activity.Elapsed.TotalSeconds:F0} s.",
                $"Saved to {fp.Path}. After you uninstall it yourself, open Saved fingerprints and scan it in external mode.");
        }
        catch (OperationCanceledException)
        {
            ShowInfo(InfoBarSeverity.Warning, "Recording cancelled.", "Nothing was saved.");
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

    private async void OnSavedFingerprints(object sender, RoutedEventArgs e)
    {
        if (!Program.Engine.IsLive)
        {
            ShowInfo(InfoBarSeverity.Informational, "Sample data.", "Saved fingerprints need the engine.");
            return;
        }
        IReadOnlyList<SavedFingerprint> list;
        try { list = await Program.Engine.ListFingerprintsAsync(); }
        catch (Exception ex) { ShowError(ex); return; }
        if (list.Count == 0)
        {
            ShowInfo(InfoBarSeverity.Informational, "No saved fingerprints yet.",
                "In Programs, Record fingerprint (or Scan leftovers) saves one.");
            return;
        }
        var choices = new ListView
        {
            ItemsSource = list.Select(f => $"{f.Name}  ·  {f.Recorded:g}  ·  {f.ProgramId}").ToList(),
            SelectionMode = ListViewSelectionMode.Single,
            SelectedIndex = 0,
            MaxHeight = 320,
        };
        var mode = new ComboBox
        {
            ItemsSource = new List<string>
            {
                "external: the program was removed outside Purge",
                "forced: the program is still installed",
                "post: Purge ran its uninstaller",
            },
            SelectedIndex = 0,
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
        var panel = new StackPanel { Spacing = 12, MinWidth = 460 };
        panel.Children.Add(choices);
        // No style lookup from code: casting a looked-up Style throws under Native AOT (ui/README.md).
        panel.Children.Add(new TextBlock { Text = "Scan mode", FontSize = 12, Opacity = 0.75 });
        panel.Children.Add(mode);
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = "Scan a saved fingerprint",
            Content = panel,
            PrimaryButtonText = "Scan",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
            RequestedTheme = MainWindow.Instance.ActualTheme,
        };
        if (await dialog.ShowAsync() != ContentDialogResult.Primary || choices.SelectedIndex < 0) return;
        var modeName = (mode.SelectedIndex switch { 1 => "forced", 2 => "post", _ => "external" });
        await ScanFingerprintAsync(list[choices.SelectedIndex], modeName);
    }

    /// <summary>
    /// Saves the plan and the current selection as files the CLI's <c>exec</c> reads (Documents\Purge exports), after
    /// <c>plan show</c> read the plan back. Nothing runs.
    /// </summary>
    private async void OnExport(object sender, RoutedEventArgs e)
    {
        if (_plan is not { } plan || _busy) return;
        var ids = _all.Where(r => !r.IsGroup && r.Checked && r.Id.Length > 0).Select(r => r.Id).ToList();
        if (ids.Count == 0) return;
        var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "Purge exports",
            $"{DateTime.Now:yyyyMMdd-HHmmss}-{Purge.Client.Cli.CliEngineClient.Slug(plan.ProgramName)}");
        try
        {
            string? show = null;
            try { show = await Program.Engine.PlanShowAsync(plan.PlanPath); }
            catch (Exception ex) when (ex is not OperationCanceledException) { show = "plan show failed: " + ex.Message; }
            var result = await Task.Run(() => PlanExport.Write(plan, ids, dir, show));
            var bar = ShowInfo(InfoBarSeverity.Success, $"Exported {result.Selected} selected {(result.Selected == 1 ? "item" : "items")}.",
                $"{result.Directory} · confirm hash {result.ConfirmHash[..12]}… · run later with: {result.CommandLine}");
            var open = new Button { Content = "Open folder" };
            open.Click += (_, _) => System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo("explorer.exe", $"\"{result.Directory}\"") { UseShellExecute = false });
            bar.ActionButton = open;
        }
        catch (Exception ex)
        {
            ShowError(ex);
        }
    }

    private async Task ShowTextAsync(string title, string text)
    {
        var dialog = new ContentDialog
        {
            XamlRoot = XamlRoot,
            Title = title,
            Content = new ScrollViewer
            {
                MaxHeight = 480,
                Content = new TextBlock { Text = text, TextWrapping = TextWrapping.Wrap, IsTextSelectionEnabled = true, FontSize = 12 },
            },
            CloseButtonText = "Close",
            RequestedTheme = MainWindow.Instance.ActualTheme,
        };
        await dialog.ShowAsync();
    }

    private void LoadPlan(LeftoverPlan plan)
    {
        _plan = plan;
        var rows = new List<LeftoverRow>();
        // Groups follow the item type (alpha); Weak items stay in their type's group and are found by the band filter.
        foreach (var type in Enum.GetValues<LeftoverType>())
        {
            var items = plan.Items.Where(i => i.Type == type).ToList();
            if (items.Count == 0) continue;
            var group = EngineDocs.Describe(type);
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
                if (i.IsUninstallNotice) why = $"Notice: consider uninstalling {i.SuggestUninstall} (Programs) · {why}";
                if (i.ObjectNote is { Name.Length: > 0 } note && i.TargetType == "FirewallRule") why = $"\"{note.Name}\" · {why}";
                var kind = i.IsFile ? LeftoverKind.File : i.IsRegistry ? LeftoverKind.Registry : LeftoverKind.Task;
                var size = i.SizeBytes is { } b ? ProgramRow.FormatSize(b)
                    : i.ChildCount is { } n ? $"{n} inside" : "";
                rows.Add(new LeftoverRow(group, i.Display, why, band, size, i.SizeBytes ?? 0, kind)
                {
                    Id = i.Id,
                    IsUserData = i.IsUserData,
                    FoundBy = $"{string.Join(" + ", i.Scanners)} · {i.Category} · {i.Action} · {i.Evidence} evidence",
                    Contents = i.ChildCount is { } c ? $"{c} files or values" + (i.SizeBytes is { } sb ? $", {ProgramRow.FormatSize(sb)}" : "") : "",
                    Checked = i.Selectable && i.Preselected,
                    Evidence = EvidenceLines(i),
                    Source = i,
                });
            }
        }
        _all = rows;
        _showWeak = true;
        WeakButton.Visibility = Visibility.Collapsed;
        _appliedPreset = Settings.Preset;
        _appliedUserData = Settings.PreSelectUserData;
        SelectButton.Content = "Select: as the engine ticked";
        FillTypeFilter();
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
        return AddInfo(severity, title, message);
    }

    /// <summary>Adds a bar below the ones already shown.</summary>
    private InfoBar AddInfo(InfoBarSeverity severity, string title, string message)
    {
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
