using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Purge.App.Shell;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>
/// Board 16 on sample data from <c>quarantine.status</c> (proposed). Put back and delete open the security prompt
/// preview; nothing moves. Expiry follows ENGINE_PLAN.md §7.8: it proposes deletion and never acts on its own.
/// </summary>
public sealed partial class VaultView : UserControl
{
    private List<VaultBatch> _batches = [];
    private bool _promptOpen;

    public VaultView()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            if (_batches.Count > 0) return;
            QuarantineStatus status;
            try { status = await Program.Engine.GetQuarantineAsync(); }
            catch (Exception e)
            {
                ShowInfo(InfoBarSeverity.Error, "Couldn't read the quarantine.", e.Message);
                return;
            }
            Fill(status);
        };
    }

    private void Fill(QuarantineStatus status)
    {
        var now = DateTimeOffset.Now;
        _batches = status.Batches.OrderByDescending(b => b.Created).Select(b => new VaultBatch(b, now)).ToList();
        Batches.ItemsSource = _batches;

        var expiring = _batches.Where(b => b.Expiring || b.Expired).ToList();
        Volumes.ItemsSource = status.Volumes
            .Select(v => new VaultVolume(v, expiring.Where(b => b.Volume == v.Volume).Sum(b => b.Source.Bytes)))
            .ToList();

        var held = _batches.Where(b => b.Held).ToList();
        Totals.Text = $"{held.Count} cleanups hold {ProgramRow.FormatSize(held.Sum(b => b.Source.Bytes))} · files 30 days, registry backups 180 days";
        EmptyButton.IsEnabled = held.Count > 0;

        if (expiring.Count > 0)
        {
            var items = expiring.Sum(b => b.Source.FileItems + b.Source.RegistryItems);
            var bytes = ProgramRow.FormatSize(expiring.Sum(b => b.Source.Bytes));
            var soonest = expiring.Min(b => b.FileDays);
            var title = soonest == 0
                ? $"{items} items ({bytes}) have expired."
                : $"{items} items ({bytes}) expire in {soonest} {(soonest == 1 ? "day" : "days")}.";
            var bar = ShowInfo(InfoBarSeverity.Warning, title,
                "After that Purge offers to delete them and asks first; nothing is deleted on its own. User data is listed one by one.");
            bar.IsClosable = true;
            var review = new Button { Content = "Review and delete…" };
            review.Click += async (_, _) => await ConfirmDelete(expiring, "expiring items");
            bar.ActionButton = review;
        }
    }

    private async void OnEmpty(object sender, RoutedEventArgs e) =>
        await ConfirmDelete(_batches.Where(b => b.Held).ToList(), "quarantine");

    private async void OnRestore(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not VaultBatch b || _promptOpen) return;
        var items = Lines(b).ToList();
        await Confirm(new ConsentSummary(b.Name, items, DateTime.Today, ConsentAction.Restore), "put back");
    }

    private void OnDetails(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("history");

    private void OnExport(object sender, RoutedEventArgs e) =>
        ShowInfo(InfoBarSeverity.Informational, "Export isn't connected yet.",
            "In M3 this saves the quarantine journal as JSON, the same file History & undo exports.");

    private async Task ConfirmDelete(List<VaultBatch> batches, string what)
    {
        if (batches.Count == 0 || _promptOpen) return;
        var items = batches.SelectMany(Lines).ToList();
        var name = batches.Count == 1 ? batches[0].Name : $"{batches.Count} cleanups";
        await Confirm(new ConsentSummary(name, items, DateTime.Today, ConsentAction.Delete), "deleted");
    }

    /// <summary>
    /// What the prompt lists. The sample has per-batch counts only, so each batch is one line, plus one line per
    /// user-data item so they are confirmed one by one (the real list comes from the quarantine journal).
    /// </summary>
    private static IEnumerable<ConsentItem> Lines(VaultBatch b)
    {
        var s = b.Source;
        var plain = s.FileItems + s.RegistryItems - s.UserDataItems;
        if (plain > 0)
            yield return new ConsentItem($"{b.Name}: {plain} items", LeftoverKind.File, Band.Safe,
                ProgramRow.FormatSize(s.Bytes), s.Bytes, false);
        for (var i = 1; i <= s.UserDataItems; i++)
            yield return new ConsentItem($"{b.Name}: user data item {i} of {s.UserDataItems}", LeftoverKind.File, Band.Likely, "", 0, true);
    }

    private async Task Confirm(ConsentSummary summary, string verb)
    {
        _promptOpen = true;
        var waiting = ShowInfo(InfoBarSeverity.Informational, "Confirm in the Purge security prompt.", "Nothing has changed yet.");
        bool ok;
        try { ok = await ConsentPrompt.ShowAsync(MainWindow.Instance.Hwnd, summary); }
        finally { _promptOpen = false; InfoBarHost.Children.Remove(waiting); }
        if (ok)
            ShowInfo(InfoBarSeverity.Success, "Confirmed in the security prompt.",
                $"This preview isn't connected to the engine, so nothing was {(verb == "put back" ? "put back" : "deleted")}.");
    }

    private InfoBar ShowInfo(InfoBarSeverity severity, string title, string message)
    {
        var bar = new InfoBar { Severity = severity, Title = title, Message = message, IsOpen = true, IsClosable = true };
        bar.RequestedTheme = MainWindow.Instance.ActualTheme;
        bar.Closed += (s, _) => InfoBarHost.Children.Remove(s);
        InfoBarHost.Children.Add(bar);
        return bar;
    }
}
