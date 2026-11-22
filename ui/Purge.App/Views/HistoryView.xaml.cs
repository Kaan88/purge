using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Purge.Client.Broker;

namespace Purge.App.Views;

/// <summary>One item of a session (<c>history.get</c>) as the detail pane binds it.</summary>
public sealed partial class HistoryItemRow(HistoryEntryModel model)
{
    public HistoryEntryModel Model { get; } = model;
    public string Name => Model.DisplayName;
    public string Kind => Model.KindText;
    public string Outcome => Model.OutcomeText;
    public bool Selectable => Model.Selectable;
    public string Alert => Model.AlertText ?? "";
    public Visibility AlertVisibility => Model.HasAlert ? Visibility.Visible : Visibility.Collapsed;

    public bool Checked
    {
        get => Model.Checked;
        set => Model.Checked = value && Model.Selectable;
    }
}

/// <summary>A day header or one cleanup session of the S4 list and timeline.</summary>
public sealed partial class HistoryRow
{
    private HistoryRow(string day) { IsDay = true; Title = day; }

    private HistoryRow(HistorySessionModel session)
    {
        Session = session;
        Title = session.Name;
        Time = session.Time;
        Tile = ProgramRow.TileFor(session.Name);
        Initial = session.Name.Length > 0 && char.IsLetterOrDigit(session.Name[0]) ? char.ToUpperInvariant(session.Name[0]).ToString() : "?";
    }

    public static HistoryRow Day(string title) => new(title);

    public static HistoryRow For(HistorySessionModel session) => new(session);

    public HistorySessionModel? Session { get; }
    public bool IsDay { get; }
    public string Title { get; }
    public string Time { get; } = "";
    public string Initial { get; } = "";
    public Brush? Tile { get; }
    public string Detail => Session?.Detail ?? "";
    public string State => Session?.State ?? "";
    public string AlertTip => "Purge found another object in quarantine in place of one of these items. Show items to see it.";

    // Board 13 timeline marker
    public double MarkWidth => IsDay ? 92 : 156;
    public string MarkRestorable => Session?.Restorable ?? "";
    public string MarkName => IsDay ? Title : $"{Title} {Time}, {MarkRestorable}";

    public Visibility DayVisibility => IsDay ? Visibility.Visible : Visibility.Collapsed;
    public Visibility OpVisibility => IsDay ? Visibility.Collapsed : Visibility.Visible;
    public Visibility AlertVisibility => Session?.HasAlert == true ? Visibility.Visible : Visibility.Collapsed;
    public Visibility UndoableVisibility => Session?.Chip == HistoryChip.Undoable ? Visibility.Visible : Visibility.Collapsed;
    public Visibility CautionVisibility => Session?.Chip == HistoryChip.Caution ? Visibility.Visible : Visibility.Collapsed;
    public Visibility NeutralVisibility => Session?.Chip == HistoryChip.Neutral ? Visibility.Visible : Visibility.Collapsed;
}

/// <summary>
/// S4 on real data: the list is <c>history.index</c> from the medium engine (no broker, no prompt to open the page);
/// "Show items" and Restore start the broker on the click. All state lives in <see cref="HistoryViewModel"/>.
/// </summary>
public sealed partial class HistoryView : UserControl
{
    private readonly HistoryViewModel _vm;
    private List<HistoryRow> _rows = [];
    private string _rowsKey = "";
    private bool _syncing;
    private bool _cancelShown;

    public HistoryView()
    {
        InitializeComponent();
        _vm = new HistoryViewModel(ct => Program.Engine.GetHistoryIndexAsync(ct), LaunchAsync);
        _vm.Changed += () => DispatcherQueue.TryEnqueue(Render);
        // The store changes under the page (a cleanup, an undo): read the index each time the page is shown.
        Loaded += (_, _) => _ = _vm.LoadAsync();
        Render();
    }

    private static async Task<HistoryBrokerLaunch> LaunchAsync(CancellationToken ct)
    {
        try
        {
            if (!await MainWindow.Instance.ConfirmFirstElevationAsync())
                return new HistoryBrokerLaunch(null, true, "");
            var result = await BrokerLauncher.LaunchAsync(BrokerLauncher.PathBesideApp(), MainWindow.Instance.Hwnd, ct);
            return result.Status switch
            {
                BrokerLaunchStatus.Started when result.Session is { } session =>
                    new HistoryBrokerLaunch(new HistoryBroker(session), false, ""),
                BrokerLaunchStatus.Cancelled => new HistoryBrokerLaunch(null, true, result.Message),
                _ => new HistoryBrokerLaunch(null, false, result.Message),
            };
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return new HistoryBrokerLaunch(null, false, e.Message);
        }
    }

    private void Render()
    {
        var phase = _vm.Phase;
        var ready = phase == HistoryPhase.Ready;
        StatePanel.Visibility = ready ? Visibility.Collapsed : Visibility.Visible;
        StripCard.Visibility = ready ? Visibility.Visible : Visibility.Collapsed;
        ListAndDetail.Visibility = ready ? Visibility.Visible : Visibility.Collapsed;
        LoadingRing.IsActive = phase == HistoryPhase.Loading;
        LoadingRing.Visibility = phase == HistoryPhase.Loading ? Visibility.Visible : Visibility.Collapsed;
        StateRetry.Visibility = phase == HistoryPhase.Error ? Visibility.Visible : Visibility.Collapsed;
        (StateTitle.Text, StateDetail.Text) = phase switch
        {
            HistoryPhase.Loading => ("Reading the history…", ""),
            HistoryPhase.Empty => ("No cleanups yet.", "Cleanups you run from Leftovers appear here, and you can put them back from here."),
            HistoryPhase.Error => ("Couldn't read the history.", _vm.Error ?? ""),
            _ => ("", ""),
        };
        if (!ready) return;
        FillRows();
        RenderDetail();
    }

    private void FillRows()
    {
        var key = string.Join("|", _vm.Sessions.Select(s => $"{s.Id}:{s.State}:{s.HasAlert}:{s.Detail}"));
        if (key != _rowsKey)
        {
            _rowsKey = key;
            _rows = BuildRows(_vm.Sessions);
            _syncing = true;
            Ops.ItemsSource = _rows;
            // The strip runs left to right, oldest first; the list stays newest first.
            Strip.ItemsSource = TimelineOrder(_rows);
            _syncing = false;
        }
        if (_vm.Selected is { } selected && _rows.FirstOrDefault(r => r.Session == selected) is { } row && Ops.SelectedItem != row)
        {
            _syncing = true;
            Ops.SelectedItem = row;
            Strip.SelectedItem = row;
            _syncing = false;
            Ops.ScrollIntoView(row);
            Strip.ScrollIntoView(row);
        }
    }

    private static List<HistoryRow> BuildRows(List<HistorySessionModel> sessions)
    {
        var rows = new List<HistoryRow>();
        var today = DateTime.Today;
        foreach (var group in sessions.GroupBy(s => s.Day))
        {
            var title = group.Key == today ? "Today"
                : group.Key == today.AddDays(-1) ? "Yesterday"
                : group.Key.ToString(group.Key.Year == today.Year ? "d MMMM" : "d MMMM yyyy", CultureInfo.CurrentCulture);
            rows.Add(HistoryRow.Day(title));
            rows.AddRange(group.Select(HistoryRow.For));
        }
        return rows;
    }

    private static List<HistoryRow> TimelineOrder(List<HistoryRow> rows)
    {
        var days = new List<List<HistoryRow>>();
        foreach (var r in rows)
        {
            if (r.IsDay) days.Add([r]);
            else days[^1].Add(r);
        }
        days.Reverse();
        return days.SelectMany(d => d.Take(1).Concat(d.Skip(1).OrderBy(r => r.Session!.Started))).ToList();
    }

    private void RenderDetail()
    {
        InfoBarHost.Children.Clear();
        if (_vm.Selected is not { } s) return;
        DTitle.Text = $"{s.Name} · {s.Started.ToLocalTime().ToString("d MMM yyyy HH:mm", CultureInfo.CurrentCulture)}";
        DSummary.Text = s.Detail;
        DExpiry.Text = s.Expiry;

        var items = _vm.Items;
        ShowItems.Visibility = items is null ? Visibility.Visible : Visibility.Collapsed;
        ShowItems.IsEnabled = !_vm.Busy;
        ItemsBorder.Visibility = items is null ? Visibility.Collapsed : Visibility.Visible;
        if (items is not null && (DItems.ItemsSource as List<HistoryItemRow>)?.Select(r => r.Model).SequenceEqual(items) != true)
            DItems.ItemsSource = items.Select(i => new HistoryItemRow(i)).ToList();
        UpdateRestore();

        if (s.Interrupted && !_vm.Busy)
        {
            // Recovery banner (design 6.3): Resume and Roll back, each through the broker's own dialog.
            var bar = ShowInfo(InfoBarSeverity.Warning, "The session was not recorded completely.",
                "Resume finishes what it started; Roll back puts back what it changed. Both ask in the Purge security prompt first.",
                closable: false);
            var buttons = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            var resume = new Button { Content = "Resume" };
            resume.Click += (_, _) => _ = _vm.RecoverAsync(rollback: false);
            var rollback = new Button { Content = "Roll back" };
            rollback.Click += (_, _) => _ = _vm.RecoverAsync(rollback: true);
            buttons.Children.Add(resume);
            buttons.Children.Add(rollback);
            bar.Content = buttons;
        }
        if (_vm.Waiting is { } waiting)
            ShowInfo(InfoBarSeverity.Informational, waiting, _vm.WaitingDetail, closable: false);
        if (_vm.RestoreTitle is { } title)
            ShowInfo(_vm.RestoreLines.Count == 0 ? InfoBarSeverity.Success : InfoBarSeverity.Warning, title,
                string.Join(" ", _vm.RestoreLines.Prepend(_vm.ActionInfo ?? "")).Trim());
        else if (_vm.ActionInfo is { } info)
            ShowInfo(InfoBarSeverity.Informational, info, "");
        if (_vm.ActionError is { } error)
            ShowInfo(InfoBarSeverity.Error, "Couldn't finish that.", error);
        // The shell's cancelled bar, once per cancelled prompt.
        if (_vm.PromptCancelled && !_cancelShown)
            MainWindow.Instance.ShowAdminPromptCancelled();
        _cancelShown = _vm.PromptCancelled;
    }

    private void UpdateRestore()
    {
        var n = _vm.CheckedCount;
        RestoreSelected.Content = $"Restore {n} selected";
        RestoreSelected.IsEnabled = n > 0 && _vm.CanRestore;
        RestoreAll.IsEnabled = _vm.CanRestore;
    }

    private void OnStripSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing) return;
        if (Strip.SelectedItem is not HistoryRow row) return;
        if (row.IsDay)
        {
            // A day marker jumps to that day's first cleanup.
            var i = _rows.IndexOf(row);
            row = _rows.Skip(i + 1).FirstOrDefault(r => !r.IsDay) ?? row;
            if (row.IsDay) return;
        }
        _vm.Select(row.Session!.Id);
    }

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_syncing) return;
        if (Ops.SelectedItem is HistoryRow { IsDay: false, Session: { } session }) _vm.Select(session.Id);
    }

    private void OnOpenVault(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("vault");

    private void OnRetryLoad(object sender, RoutedEventArgs e) => _ = _vm.LoadAsync();

    private void OnShowItems(object sender, RoutedEventArgs e) => _ = _vm.ShowItemsAsync();

    private void OnItemCheck(object sender, RoutedEventArgs e) => UpdateRestore();

    private void OnRestore(object sender, RoutedEventArgs e) =>
        _ = _vm.RestoreAsync(all: (sender as FrameworkElement)?.Tag as string == "all");

    private InfoBar ShowInfo(InfoBarSeverity severity, string title, string message, bool closable = true)
    {
        var bar = new InfoBar { Severity = severity, Title = title, Message = message, IsOpen = true, IsClosable = closable };
        // Pin to the window theme: code-made InfoBars otherwise take the warning/info fill from the app theme
        // (Windows setting), not from Settings → Appearance.
        bar.RequestedTheme = MainWindow.Instance.ActualTheme;
        bar.Closed += (s, _) => InfoBarHost.Children.Remove(s);
        InfoBarHost.Children.Add(bar);
        return bar;
    }
}
