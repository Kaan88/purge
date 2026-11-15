using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;
using Windows.Storage.Pickers;

namespace Purge.App.Views;

/// <summary>
/// Board 14. Counts come from the inventory, sizes and <c>quarantine.status</c>; "Reclaimable" uses the sample leftover
/// scan (no real scan yet). Dropping or browsing shows what would be scanned; nothing is connected yet.
/// </summary>
public sealed partial class HomeView : UserControl
{
    private bool _loaded;

    public HomeView()
    {
        InitializeComponent();
        Subtitle.Text = $"Last checked {DateTime.Now.ToString("HH:mm", CultureInfo.CurrentCulture)} · " +
                        "files Purge removes can be put back for 30 days";

        var safe = ReviewView.Sample().Where(r => !r.IsGroup && r.Band == Band.Safe).ToList();
        StatReclaim.Text = ProgramRow.FormatSize(safe.Sum(r => r.SizeBytes));
        StatReclaimSub.Text = $"{safe.Count} Safe items in the last scan (sample)";

        Loaded += async (_, _) =>
        {
            if (_loaded) return;
            _loaded = true;
            await LoadAsync();
        };
    }

    private async Task LoadAsync()
    {
        try
        {
            var start = await Program.Startup;
            StatPrograms.Text = start.Inventory.Entries.Count.ToString(CultureInfo.CurrentCulture);
            var sizes = await Program.Engine.GetSizesAsync();
            var total = start.Inventory.Entries.Sum(e => sizes.TryGetValue(e.ProgramId, out var s) ? s : 0);
            StatProgramsSub.Text = $"{ProgramRow.FormatSize(total)} on disk";
        }
        catch (Exception e) { StatProgramsSub.Text = "Couldn't read the list: " + e.Message; }

        try
        {
            var q = await Program.Engine.GetQuarantineAsync();
            var now = DateTimeOffset.Now;
            var batches = q.Batches.Select(b => new VaultBatch(b, now)).ToList();
            var held = batches.Where(b => b.Held).ToList();
            StatVault.Text = ProgramRow.FormatSize(held.Sum(b => b.Source.Bytes));
            StatVaultSub.Text = $"{held.Count} {(held.Count == 1 ? "cleanup" : "cleanups")} · can be put back";

            var expiring = batches.Where(b => b.Expiring || b.Expired).ToList();
            if (expiring.Count > 0)
            {
                var items = expiring.Sum(b => b.Source.FileItems + b.Source.RegistryItems);
                var soonest = expiring.Min(b => b.FileDays);
                ExpiryTitle.Text = soonest == 0
                    ? $"{items} quarantined items have expired"
                    : $"{items} quarantined items expire in {soonest} {(soonest == 1 ? "day" : "days")}";
                ExpiryText.Text = $"{ProgramRow.FormatSize(expiring.Sum(b => b.Source.Bytes))}. Purge will offer to delete them and ask first; " +
                                  "nothing is deleted on its own, and user data is listed one by one.";
                ExpiryCard.Visibility = Visibility.Visible;
            }
        }
        catch (Exception e) { StatVaultSub.Text = "Couldn't read the quarantine: " + e.Message; }
    }

    private void OnOpenPage(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is string key) MainWindow.Instance.Navigate(key);
    }

    private void OnQueueLauncher(object sender, RoutedEventArgs e)
    {
        QueueLauncher.IsEnabled = false;
        QueueLauncher.Content = "In the queue";
        ShowInfo(InfoBarSeverity.Informational, "Python Launcher added to the uninstall queue (preview).",
            "Nothing runs until you start the queue.");
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        e.AcceptedOperation = DataPackageOperation.Link;
        e.DragUIOverride.Caption = "Find what it left behind";
        DropTitle.Text = "Release to look for leftovers";
    }

    private void OnDragLeave(object sender, DragEventArgs e) => DropTitle.Text = "Drop a program or folder here";

    private async void OnDrop(object sender, DragEventArgs e)
    {
        DropTitle.Text = "Drop a program or folder here";
        if (!e.DataView.Contains(StandardDataFormats.StorageItems)) return;
        var items = await e.DataView.GetStorageItemsAsync();
        if (items.Count > 0) Picked(items[0]);
    }

    private async void OnBrowse(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.ComputerFolder };
            picker.FileTypeFilter.Add(".exe");
            picker.FileTypeFilter.Add(".lnk");
            WinRT.Interop.InitializeWithWindow.Initialize(picker, MainWindow.Instance.Hwnd);
            if (await picker.PickSingleFileAsync() is { } file) Picked(file);
        }
        catch (Exception ex)
        {
            ShowInfo(InfoBarSeverity.Error, "Couldn't open the file picker.", ex.Message);
        }
    }

    private void Picked(IStorageItem item) =>
        ShowInfo(InfoBarSeverity.Informational, $"Purge would look for what {item.Name} left behind.",
            "Scanning a dropped program isn't connected to the engine yet. Nothing was read or changed.");

    private void ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        InfoBarHost.Children.Clear();
        var bar = new InfoBar { Severity = severity, Title = title, Message = message, IsOpen = true, IsClosable = true };
        bar.RequestedTheme = MainWindow.Instance.ActualTheme;
        bar.Closed += (s, _) => InfoBarHost.Children.Remove(s);
        InfoBarHost.Children.Add(bar);
    }
}
