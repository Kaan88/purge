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
    private bool _cancelShown;

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
                return new VaultBrokerLaunch(null, true, "");
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
        var key = string.Join("|", _vm.Batches.Select(b => $"{b.Id}:{b.State}:{b.Detail}")) + "#" +
                  string.Join("|", _vm.Volumes.Select(v => $"{v.Root}:{v.Used}:{v.Cap}"));
        if (key != _rowsKey)
        {
            _rowsKey = key;
            Batches.ItemsSource = _vm.Batches.Select(b => new VaultBatch(b)).ToList();
            Volumes.ItemsSource = _vm.Volumes.Select(v => new VaultVolume(v)).ToList();
        }
        Totals.Text = _vm.Phase == VaultPhase.Ready ? _vm.Totals : "";
        var expired = _vm.ExpiredBatches.ToList();
        ReviewButton.IsEnabled = !_vm.Busy && expired.Count > 0;

        InfoBarHost.Children.Clear();
        switch (_vm.Phase)
        {
            case VaultPhase.Loading:
                ShowInfo(InfoBarSeverity.Informational, "Reading the quarantine…", "");
                break;
            case VaultPhase.Error:
                ShowInfo(InfoBarSeverity.Error, "Couldn't read the quarantine.", _vm.Error ?? "");
                break;
            case VaultPhase.Empty:
                ShowInfo(InfoBarSeverity.Informational, "The quarantine is empty.",
                    "Cleanups you run from Leftovers appear here, with Put back.");
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
        // The shell's cancelled bar, once per cancelled prompt.
        if (_vm.PromptCancelled && !_cancelShown)
            MainWindow.Instance.ShowAdminPromptCancelled();
        _cancelShown = _vm.PromptCancelled;
    }

    private void OnRestore(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is VaultBatch b) _ = _vm.RestoreAsync(b.Id);
    }

    private void OnReviewExpired(object sender, RoutedEventArgs e) => _ = _vm.ReviewExpiredAsync();

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
