using System.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Purge.App.Shell;

namespace Purge.App.Views;

/// <summary>One quarantined item of a session.</summary>
public sealed partial class HistoryItem(string path, string size, bool isChecked)
{
    public string Path { get; } = path;
    public string Size { get; } = size;
    public bool Checked { get; set; } = isChecked;
}

/// <summary>A day header or one cleanup session of the S4 list.</summary>
public sealed partial class HistoryRow
{
    private HistoryRow(string title) { IsDay = true; Title = title; }

    public HistoryRow(string title, string time, string detail, string state, string publisher, string summary,
        string note, string expiry, List<HistoryItem> items)
    {
        Title = title;
        Time = time;
        Detail = detail;
        State = state;
        Tile = ProgramRow.TileFor(publisher);
        Initial = title[..1];
        Summary = summary;
        Note = note;
        _expiry = expiry;
        Items = items;
    }

    public static HistoryRow Day(string title) => new(title);

    public bool IsDay { get; }
    public string Title { get; }
    public string Time { get; } = "";
    public string Detail { get; } = "";
    public string State { get; } = "";
    public string Initial { get; } = "";
    public Brush? Tile { get; }
    public string Summary { get; } = "";
    public string Note { get; } = "";
    private readonly string _expiry = "";
    public List<HistoryItem> Items { get; } = [];

    /// <summary>When the cleanup ran; retention counts from here (ENGINE_PLAN.md §7.8).</summary>
    public DateTimeOffset Created { get; init; }

    /// <summary>Still something in quarantine to put back.</summary>
    public bool Held => !IsDay && State is "Undoable" or "Partial";

    private int FileDays => Retention.DaysLeft(Created, Retention.FileDays, DateTimeOffset.Now);
    private int BackupDays => Retention.DaysLeft(Created, Retention.BackupDays, DateTimeOffset.Now);

    public string Expiry => !Held ? _expiry
        : $"Files restorable until {Created.AddDays(Retention.FileDays).ToString("d MMM yyyy", CultureInfo.CurrentCulture)} ({FileDays} days), " +
          $"registry and task backups until {Created.AddDays(Retention.BackupDays).ToString("d MMM yyyy", CultureInfo.CurrentCulture)}";

    // Board 13 timeline marker
    public double MarkWidth => IsDay ? 92 : 156;
    public string MarkTitle => Title;
    public string MarkRestorable => IsDay ? "" : !Held ? "Nothing to restore"
        : FileDays > 0 ? $"Files {FileDays} d · registry {BackupDays} d" : $"Files expired · registry {BackupDays} d";
    public string MarkName => IsDay ? Title : $"{Title} {Time}, {MarkRestorable}";

    public Visibility DayVisibility => IsDay ? Visibility.Visible : Visibility.Collapsed;
    public Visibility OpVisibility => IsDay ? Visibility.Collapsed : Visibility.Visible;
    public Visibility UndoableVisibility => !IsDay && State == "Undoable" ? Visibility.Visible : Visibility.Collapsed;
    public Visibility PartialVisibility => !IsDay && State == "Partial" ? Visibility.Visible : Visibility.Collapsed;
    public Visibility NeutralVisibility => !IsDay && State is "Restored" or "Kept all" ? Visibility.Visible : Visibility.Collapsed;
}

/// <summary>S4 on sample data. Restore buttons only report what they would do.</summary>
public sealed partial class HistoryView : UserControl
{
    private HistoryRow? _current;
    private readonly List<HistoryRow> _rows = Sample();
    private bool _syncing;

    public HistoryView()
    {
        InitializeComponent();
        Ops.ItemsSource = _rows;
        // The strip runs left to right, oldest first; the list stays newest first.
        Strip.ItemsSource = TimelineOrder(_rows);
        Ops.SelectedItem = _rows[1];
        Loaded += (_, _) => { if (Strip.SelectedItem is { } s) Strip.ScrollIntoView(s); };
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
        return days.SelectMany(d => d.Take(1).Concat(d.Skip(1).OrderBy(r => r.Created))).ToList();
    }

    /// <summary>Selects the newest cleanup of a program (from the command box).</summary>
    public void Select(string programName)
    {
        if (_rows.FirstOrDefault(r => !r.IsDay && r.Title == programName) is { } row)
        {
            Ops.SelectedItem = row;
            Ops.ScrollIntoView(row);
        }
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
        _syncing = true;
        Strip.SelectedItem = row;
        Ops.SelectedItem = row;
        Ops.ScrollIntoView(row);
        _syncing = false;
    }

    private void OnOpenVault(object sender, RoutedEventArgs e) => MainWindow.Instance.Navigate("vault");

    private void OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (Ops.SelectedItem is not HistoryRow { IsDay: false } row) return;
        if (!_syncing)
        {
            _syncing = true;
            Strip.SelectedItem = row;
            Strip.ScrollIntoView(row);
            _syncing = false;
        }
        _current = row;
        DTitle.Text = $"{row.Title} · {row.Time}";
        DSummary.Text = row.Summary;
        DItems.ItemsSource = row.Items;
        DNote.Text = row.Note;
        DExpiry.Text = row.Expiry;
        UpdateRestore();
    }

    private void OnItemCheck(object sender, RoutedEventArgs e) => UpdateRestore();

    private void UpdateRestore()
    {
        var n = _current?.Items.Count(i => i.Checked) ?? 0;
        RestoreSelected.Content = $"Restore {n} selected";
        RestoreSelected.IsEnabled = n > 0 && _current?.Held == true;
        RestoreAll.IsEnabled = _current?.Held == true;
    }

    private async void OnRestore(object sender, RoutedEventArgs e)
    {
        if (_current is not { Held: true } row) return;
        var items = ((sender as FrameworkElement)?.Tag as string == "all" ? row.Items : row.Items.Where(i => i.Checked))
            .Select(i => new ConsentItem(i.Path, i.Path.StartsWith("HK", StringComparison.Ordinal) ? LeftoverKind.Registry : LeftoverKind.File,
                Band.Safe, i.Size, 0, false))
            .ToList();
        if (items.Count == 0) return;
        // Putting back writes to protected places, so it goes through the broker's security prompt like moving.
        var waiting = ShowInfo(InfoBarSeverity.Informational, "Confirm in the Purge security prompt.", "Nothing has been put back yet.");
        var ok = await ConsentPrompt.ShowAsync(MainWindow.Instance.Hwnd,
            new ConsentSummary(row.Title, items, DateTime.Today, ConsentAction.Restore));
        InfoBarHost.Children.Remove(waiting);
        if (ok)
            ShowInfo(InfoBarSeverity.Success, "Confirmed in the security prompt.",
                "This preview isn't connected to the engine, so nothing was put back.");
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

    private void OnSample(object sender, RoutedEventArgs e) { }

    private static DateTimeOffset Today(int h, int m) => new DateTimeOffset(DateTime.Today).AddHours(h).AddMinutes(m);

    private static List<HistoryRow> Sample()
    {
        const string undoNote = "Undo puts the leftovers back exactly as they were. It doesn't reinstall the program: run its installer for that.";
        return
        [
            HistoryRow.Day("Today"),
            new("Mozilla Firefox", "04:14", "Uninstalled · 8 leftovers removed · 2.7 MB", "Undoable", "Mozilla",
                "Uninstaller ran (exit 0), then 8 leftovers moved to quarantine. Restore point \u201CPurge: before removing 3 programs\u201D.",
                "Undo puts the leftovers back exactly as they were. It doesn't reinstall Firefox: run its installer for that.",
                @"Expires 11 Dec 2026 · stored in C:\ProgramData\Purge\quarantine\2026-11-11T0414",
                [
                    new(@"C:\Users\tester\AppData\Local\Mozilla", "2.6 MB", true),
                    new(@"C:\ProgramData\Mozilla-1de4eec8-…", "96 KB", true),
                    new(@"HKCU\Software\Mozilla\Firefox", "12 values", true),
                    new(@"HKLM\Software\Mozilla\Firefox", "4 values", false),
                    new(@"Classes\…\OpenWithProgids (7 values)", "7 values", false),
                    new("Task: Firefox Default Browser Agent", "", false),
                ]) { Created = Today(4, 14) },
            new("Python 3.12.7 (64-bit)", "04:16", "Uninstalled · 1 file in use, removed after restart · 6 leftovers", "Partial",
                "Python Software Foundation",
                "Uninstaller ran (exit 0). 5 leftovers moved to quarantine; 1 file was in use and was removed at the next restart.",
                undoNote, @"Expires 11 Dec 2026 · stored in C:\ProgramData\Purge\quarantine\2026-11-11T0416",
                [
                    new(@"C:\Users\tester\AppData\Local\Programs\Python\Python312", "3.4 MB", true),
                    new(@"HKCU\Software\Python\PythonCore\3.12", "9 values", true),
                    new(@"C:\Users\tester\AppData\Roaming\Python\Python312", "1.1 MB", false),
                    new(@"C:\Users\tester\AppData\Local\pip", "412 MB", false),
                ]) { Created = Today(4, 16) },
            new("Notepad++", "03:58", "Uninstalled · 2 leftovers removed, then restored at 04:02", "Restored", "Notepad++ Team",
                "Uninstaller ran (exit 0), 2 leftovers moved to quarantine, then you restored both at 04:02.",
                "Nothing of Notepad++ is in quarantine any more.", "Restored 04:02",
                [
                    new(@"C:\Users\tester\AppData\Roaming\Notepad++", "180 KB", false),
                    new(@"HKCU\Software\Notepad++", "3 values", false),
                ]) { Created = Today(3, 58) },
            HistoryRow.Day("10 November"),
            new("Microsoft Visual Studio Code", "22:41", "Uninstalled · 141 leftovers removed (135 file-type values) · 28.4 MB", "Undoable",
                "Microsoft Corporation",
                "Uninstaller ran (exit 0), then 141 leftovers moved to quarantine, 135 of them file-type values.",
                undoNote, @"Expires 10 Dec 2026 · stored in C:\ProgramData\Purge\quarantine\2026-11-10T2241",
                [
                    new(@"C:\Users\tester\AppData\Roaming\Code", "27.9 MB", true),
                    new(@"Classes\…\OpenWithProgids (135 values)", "135 values", true),
                    new(@"HKCU\Software\Classes\vscode", "4 keys", true),
                ]) { Created = new DateTimeOffset(2026, 11, 10, 22, 41, 0, DateTimeOffset.Now.Offset) },
            new("7-Zip 24.08", "22:30", "Uninstalled · 1 shell extension entry found, kept by you", "Kept all", "Igor Pavlov",
                "Uninstaller ran (exit 0). Purge found 1 shell extension entry and you chose to keep it.",
                "Nothing was moved, so there is nothing to restore.", "Nothing in quarantine",
                [new(@"HKCR\*\shellex\ContextMenuHandlers\7-Zip", "1 key", false)])
            { Created = new DateTimeOffset(2026, 11, 10, 22, 30, 0, DateTimeOffset.Now.Offset) },
        ];
    }
}
