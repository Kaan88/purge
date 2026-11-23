using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Purge.Client.Broker;

namespace Purge.App.Views;

/// <summary>
/// Board 16 on real data (design 7a page table): use and real cap per volume and the cleanups that hold something,
/// from <c>history.index</c> on the medium engine (no broker, no prompt to open the page). "Put back…" and "Review
/// and delete…" start the broker on the click; its own dialogs ask before anything changes. All state lives in
/// <see cref="VaultViewModel"/>.
/// </summary>
public sealed partial class VaultView : UserControl
{
    private readonly VaultViewModel _vm;
    private string _rowsKey = "";
    private string _itemsKey = "";
    private List<VaultBatch> _rows = [];

    public VaultView()
    {
        InitializeComponent();
        _vm = new VaultViewModel(ct => Program.Engine.GetHistoryIndexAsync(ct), LaunchAsync);
        _vm.Changed += () => DispatcherQueue.TryEnqueue(Render);
        // The store changes under the page (a cleanup, an undo): read the index each time the page is shown.
        Loaded += (_, _) => _ = _vm.LoadAsync();
        Render();
    }

    private static async Task<VaultBrokerLaunch> LaunchAsync(CancellationToken ct)
    {
        try
        {
            if (!await MainWindow.Instance.ConfirmFirstElevationAsync())
                return new VaultBrokerLaunch(null, true, "", DeclinedExplanation: true);
            var result = await BrokerLauncher.LaunchAsync(BrokerLauncher.PathBesideApp(), ct);
            return result.Status switch
            {
                BrokerLaunchStatus.Started when result.Session is { } session =>
                    new VaultBrokerLaunch(new HistoryBroker(session), false, ""),
                BrokerLaunchStatus.Cancelled => new VaultBrokerLaunch(null, true, result.Message),
                _ => new VaultBrokerLaunch(null, false, result.Message),
            };
        }
        catch (Exception e) when (e is not OutOfMemoryException)
        {
            return new VaultBrokerLaunch(null, false, e.Message);
        }
    }

    private void Render()
    {
        // The summary is in the key: a "Delete now" of some items changes a cleanup's bytes and nothing else.
        var key = string.Join("|", _vm.Batches.Select(b => $"{b.Id}:{b.State}:{b.Detail}:{b.Summary}")) + "#" +
                  string.Join("|", _vm.Volumes.Select(v => $"{v.Root}:{v.Used}:{v.Cap}"));
        if (key != _rowsKey)
        {
            _rowsKey = key;
            _rows = _vm.Batches.Select(b => new VaultBatch(b)).ToList();
            Batches.ItemsSource = _rows;
            Volumes.ItemsSource = _vm.Volumes.Select(v => new VaultVolume(v)).ToList();
        }
        // While a broker action runs (its prompt may be open), every row action is disabled.
        foreach (var row in _rows) row.CanAct = !_vm.Busy;
        var itemsKey = _vm.ItemsFor is null ? ""
            : $"{_vm.ItemsFor}:{_vm.Busy}:" + string.Join("|", _vm.Items.Select(i => i.ExpiryId));
        if (itemsKey != _itemsKey)
        {
            _itemsKey = itemsKey;
            ItemsPanel.Visibility = _vm.ItemsFor is null ? Visibility.Collapsed : Visibility.Visible;
            ItemsTitle.Text = _vm.ItemsFor is null ? "" : $"In quarantine from {_vm.ItemsName}";
            Items.ItemsSource = _vm.Items.Select(i => new VaultItem(i, !_vm.Busy)).ToList();
        }
        Totals.Text = _vm.Phase == VaultPhase.Ready ? _vm.Totals : "";
        var expired = _vm.ExpiredBatches.ToList();
        ReviewButton.IsEnabled = !_vm.Busy && expired.Count > 0;
        // Why it is off, on the host (a disabled button shows no tooltip).
        ToolTipService.SetToolTip(ReviewHost, ReviewButton.IsEnabled ? null
            : _vm.Busy ? "Wait until the current action has finished."
            : "Nothing has passed its retention yet. \"Delete now\" on a cleanup deletes it sooner.");

        InfoBarHost.Children.Clear();
        EmptyCard.Visibility = _vm.Phase == VaultPhase.Empty ? Visibility.Visible : Visibility.Collapsed;
        switch (_vm.Phase)
        {
            case VaultPhase.Loading:
                ShowInfo(InfoBarSeverity.Informational, "Reading the quarantine…", "");
                break;
            case VaultPhase.Error:
                ShowInfo(InfoBarSeverity.Error, "Couldn't read the quarantine.", _vm.Error ?? "");
                break;
        }
        if (_vm.Interrupted > 0)
        {
            var bar = ShowInfo(InfoBarSeverity.Warning, "An earlier cleanup was interrupted.",
                "Resume or roll it back from History & undo before the next change.");
            var open = new Button { Content = "Open History & undo" };
            open.Click += (_, _) => MainWindow.Instance.Navigate("history");
            bar.ActionButton = open;
        }
        if (expired.Count > 0 && !_vm.Busy)
        {
            var bar = ShowInfo(InfoBarSeverity.Warning,
                expired.Count == 1 ? "One cleanup is past its retention." : $"{expired.Count} cleanups are past their retention.",
                "Purge offers to delete expired items and asks first in its security prompt; nothing is deleted on its own. " +
                "User data is asked for one item at a time.");
            var review = new Button { Content = "Review and delete…" };
            review.Click += (_, _) => _ = _vm.ReviewExpiredAsync();
            bar.ActionButton = review;
        }
        if (_vm.Waiting is { } waiting)
            ShowInfo(InfoBarSeverity.Informational, waiting, "Nothing has changed yet.");
        if (_vm.ResultTitle is { } title)
            ShowInfo(_vm.ActionInfo is null ? InfoBarSeverity.Success : InfoBarSeverity.Warning, title, _vm.ActionInfo ?? "");
        else if (_vm.ActionInfo is { } info)
            ShowInfo(InfoBarSeverity.Informational, info, "");
        if (_vm.ActionError is { } error)
            ShowInfo(InfoBarSeverity.Error, "Couldn't finish that.", error);
        // A declined or cancelled admin prompt is said by the page's own line (ActionInfo), not the window's bar.
    }

    private void OnRestore(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is VaultBatch b) _ = _vm.RestoreAsync(b.Id);
    }

    private void OnReviewExpired(object sender, RoutedEventArgs e) => _ = _vm.ReviewExpiredAsync();

    // "Delete now": the page asks one thing of its own, whether the registry backups go too (off each time, DECISIONS
    // 2026-11-24). It is a choice, not the confirmation: the broker's prompts name every item and backup and are the gate.
    private void OnDeleteNow(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { DataContext: VaultBatch b } anchor) return;
        var model = b.Model;
        var also = new CheckBox
        {
            Content = new TextBlock { Text = VaultBatchModel.AlsoBackupsText, TextWrapping = TextWrapping.Wrap },
            IsChecked = false,
            Visibility = model.CanDeleteBackups ? Visibility.Visible : Visibility.Collapsed,
        };
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(also, VaultBatchModel.AlsoBackupsText);
        var go = new Button { Content = "Continue to the security prompt…", IsEnabled = model.CanDeleteNow(false) };
        var panel = new StackPanel { Spacing = 10, MaxWidth = 340, RequestedTheme = MainWindow.Instance.ActualTheme };
        panel.Children.Add(new TextBlock { Text = model.DeleteNowIntro, TextWrapping = TextWrapping.Wrap, FontSize = 13 });
        panel.Children.Add(also);
        panel.Children.Add(go);
        var flyout = new Flyout { Content = panel };
        void Sync(object s, RoutedEventArgs a) => go.IsEnabled = model.CanDeleteNow(also.IsChecked == true);
        also.Checked += Sync;
        also.Unchecked += Sync;
        go.Click += (_, _) =>
        {
            flyout.Hide();
            _ = _vm.DeleteNowAsync(b.Id, also.IsChecked == true);
        };
        flyout.ShowAt(anchor);
    }

    private void OnChooseItems(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is VaultBatch b) _ = _vm.ShowItemsAsync(b.Id);
    }

    private void OnDeleteItemNow(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is VaultItem i) _ = _vm.DeleteItemNowAsync(i.ExpiryId);
    }

    private void OnCloseItems(object sender, RoutedEventArgs e) => _vm.CloseItems();

    private void OnDetails(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("history");

    private InfoBar ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        var bar = new InfoBar { Severity = severity, Title = title, Message = message, IsOpen = true, IsClosable = false };
        // Pin to the window theme: code-made InfoBars otherwise take their fill from the app theme.
        bar.RequestedTheme = MainWindow.Instance.ActualTheme;
        InfoBarHost.Children.Add(bar);
        return bar;
    }
}
