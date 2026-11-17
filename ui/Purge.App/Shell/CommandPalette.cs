using System.Globalization;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Purge.App.Views;

namespace Purge.App.Shell;

/// <summary>
/// Board 05: the title-bar search box doubles as a command palette (Ctrl+K or Ctrl+F). Suggestions are grouped
/// Actions, Programs, History and matched deterministically (no ranking model, no fuzzy scores: prefix, then word
/// prefix, then substring, ties by name). Every command calls the same code as its button, so it asks for the same
/// confirmation. Attached on the first rendering tick; suggestion rows are built only while typing.
/// </summary>
public sealed class CommandPalette
{
    private sealed record Entry(string Group, string Title, string Sub, string? Glyph, Brush? Tile, string? Initial, Action? Run);

    private static readonly (string[] Words, string Key, string Title, string Glyph)[] Pages =
    [
        (["home"], "home", "Home", ""),
        (["programs", "apps", "list"], "programs", "Programs", ""),
        (["queue"], "queue", "Uninstall queue", ""),
        (["leftovers", "review"], "leftovers", "Leftovers", ""),
        (["quarantine", "vault"], "vault", "Quarantine", ""),
        (["history", "undo", "log"], "history", "History & undo", ""),
        (["footprint", "map", "space"], "footprint", "Footprint", ""),
        (["startup"], "startup", "Startup", ""),
        (["assistant", "ai"], "assistant", "Assistant", ""),
        (["settings", "options", "preferences", "theme"], "settings", "Settings", ""),
    ];

    private enum Verb { None, Uninstall, Force, Scan, Undo, Modify }

    private static readonly (string Word, Verb Verb)[] Verbs =
    [
        ("uninstall", Verb.Uninstall), ("remove", Verb.Uninstall), ("delete", Verb.Uninstall),
        ("force", Verb.Force), ("scan", Verb.Scan), ("leftovers", Verb.Scan),
        ("undo", Verb.Undo), ("restore", Verb.Undo), ("modify", Verb.Modify), ("repair", Verb.Modify),
    ];

    private readonly AutoSuggestBox _box;
    private readonly Func<ProgramsView> _programs;
    private List<Client.Model.QuarantineBatch>? _history;
    private List<Entry> _current = [];

    public CommandPalette(AutoSuggestBox box, Func<ProgramsView> programs)
    {
        _box = box;
        _programs = programs;
        _box.UpdateTextOnSelect = false;
        _box.TextChanged += OnTextChanged;
        _box.QuerySubmitted += OnQuerySubmitted;
        _box.GotFocus += async (_, _) =>
        {
            if (_history is not null) return;
            try { _history = (await Program.Engine.GetQuarantineAsync()).Batches; }
            catch { _history = []; }
            if (_box.Text.Trim().Length > 0) Suggest(_box.Text);
        };
    }

    /// <summary>Puts text in the box as if typed (<c>--query</c>, for screenshots and tests).</summary>
    public void Type(string text)
    {
        _box.Focus(FocusState.Programmatic);
        _box.Text = text;
        if (MainWindow.Instance.CurrentPage == "programs") _programs().SetSearch(Parse(text).Target);
        Suggest(text);
    }

    public void Focus()
    {
        _box.Focus(FocusState.Keyboard);
        if (_box.Text.Length > 0) Suggest(_box.Text);
    }

    private void OnTextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
    {
        if (args.Reason != AutoSuggestionBoxTextChangeReason.UserInput) return;
        if (MainWindow.Instance.CurrentPage == "programs") _programs().SetSearch(Parse(sender.Text).Target);
        Suggest(sender.Text);
    }

    private void OnQuerySubmitted(AutoSuggestBox sender, AutoSuggestBoxQuerySubmittedEventArgs args)
    {
        var entry = args.ChosenSuggestion is FrameworkElement { Tag: Entry chosen } ? chosen : _current.FirstOrDefault(e => e.Run is not null);
        if (entry?.Run is null) return;
        sender.IsSuggestionListOpen = false;
        sender.Text = "";
        entry.Run();
    }

    private void Suggest(string text)
    {
        _current = Build(text);
        _box.ItemsSource = _current.Count == 0 ? null : _current.Select(Render).ToList();
        _box.IsSuggestionListOpen = _current.Count > 0;
    }

    /// <summary>Splits off the first verb ("remove fire" → Uninstall, "fire"). The rest names the program.</summary>
    private static (Verb Verb, string Target, List<string> Words) Parse(string text)
    {
        var words = text.Trim().ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries).ToList();
        foreach (var (w, v) in Verbs)
        {
            var i = words.FindIndex(x => x == w || (x.Length >= 3 && w.StartsWith(x, StringComparison.Ordinal)));
            if (i < 0) continue;
            // A lone partial word ("mod", "for") may be a verb or the start of a name: keep it as the name too.
            if (words.Count == 1 && words[0] != w) return (v, words[0], []);
            words.RemoveAt(i);
            return (v, string.Join(' ', words), words);
        }
        return (Verb.None, string.Join(' ', words), words);
    }

    private List<Entry> Build(string text)
    {
        var q = text.Trim().ToLowerInvariant();
        if (q.Length == 0) return [];
        var (verb, target, words) = Parse(text);

        var programs = _programs().All;
        var matches = target.Length == 0 ? [] : programs
            .Select(p => (Row: p, Rank: Rank(p.Name, target)))
            .Where(m => m.Rank < 3)
            .OrderBy(m => m.Rank).ThenBy(m => m.Row.Name, StringComparer.OrdinalIgnoreCase)
            .Take(5).Select(m => m.Row).ToList();
        var best = matches.FirstOrDefault();

        var actions = new List<Entry>();
        if (best is not null)
        {
            var name = best.Name;
            // UI alpha: scanning is the only action on a program; uninstalling waits for the M3 broker.
            if (Alpha.On && verb is Verb.None or Verb.Uninstall or Verb.Force or Verb.Scan)
                actions.Add(new("Actions", $"Scan {name} for leftovers", "Records it and scans while it is still installed · nothing is removed",
                    "", null, null, () => OnProgram(best, "force")));
            else if (verb is Verb.None or Verb.Uninstall)
                actions.Add(new("Actions", $"Uninstall {name}, then look for leftovers", "Runs its own uninstaller · you confirm first", "", null, null,
                    () => OnProgram(best, "uninstall")));
            if (!Alpha.On && verb is Verb.Force or Verb.Uninstall)
                actions.Add(new("Actions", $"Force remove {name} without its uninstaller", "Nothing is pre-selected afterwards", "", null, null,
                    () => OnProgram(best, "force")));
            if (verb is Verb.Modify)
                actions.Add(new("Actions", $"Modify {name}", "Opens its own setup", "", null, null, () => OnProgram(best, "modify")));
            if (!Alpha.On && verb is Verb.Scan or Verb.Uninstall)
                actions.Add(new("Actions", $"Scan {name} leftovers only", "Use after removing it another way", "", null, null,
                    () => MainWindow.Instance.Navigate("leftovers")));
        }
        foreach (var (pageWords, key, title, glyph) in Pages)
            if (pageWords.Any(w => w.StartsWith(q, StringComparison.Ordinal) || (verb == Verb.None && words.Count == 1 && w == words[0])))
                actions.Add(new("Actions", $"Go to {title}", "", glyph, null, null, () => MainWindow.Instance.Navigate(key)));

        var programEntries = matches.Select(p => new Entry("Programs", p.Name,
            string.Join(" · ", new[] { p.Version, p.SizeText }.Where(s => s.Length > 0)), null, p.TileBrush, p.Initial,
            () => OnProgram(p, null))).ToList();

        var history = new List<Entry>();
        if (_history is not null && (target.Length > 0 || verb == Verb.Undo))
        {
            foreach (var b in _history
                         .Where(b => target.Length == 0 || Rank(b.ProgramName, target) < 3)
                         .Where(b => b.State is Client.Model.BatchState.Undoable or Client.Model.BatchState.Partial)
                         .OrderByDescending(b => b.Created).Take(3))
            {
                var items = b.FileItems + b.RegistryItems;
                var days = Retention.DaysLeft(b.Created, Retention.FileDays, DateTimeOffset.Now);
                history.Add(new("History", $"Undo \"{b.ProgramName}\" cleanup from {b.Created.ToLocalTime().ToString("d MMM HH:mm", CultureInfo.CurrentCulture)}",
                    $"{items} items · {ProgramRow.FormatSize(b.Bytes)} · files restorable for {days} more days", "", null, null,
                    () =>
                    {
                        MainWindow.Instance.Navigate("history");
                        (MainWindow.Instance.CurrentView as HistoryView)?.Select(b.ProgramName);
                    }));
            }
        }

        // A typed verb puts actions first; a bare name puts the program first.
        var groups = verb != Verb.None ? new[] { actions, programEntries, history } : new[] { programEntries, actions, history };
        var result = new List<Entry>();
        foreach (var g in groups.Where(g => g.Count > 0))
        {
            result.Add(new(g[0].Group, g[0].Group.ToUpperInvariant(), "", null, null, null, null));
            result.AddRange(g);
        }
        if (result.Count > 0)
            result.Add(new("", "Enter runs the first action · every action still asks you to confirm", "", null, null, null, null));
        return result;
    }

    /// <summary>0 name starts with the query, 1 a word starts with it, 2 contains it, 3 no match.</summary>
    private static int Rank(string name, string q)
    {
        var n = name.ToLowerInvariant();
        if (n.StartsWith(q, StringComparison.Ordinal)) return 0;
        if (n.Split(' ', '-', '(', '.').Any(w => w.StartsWith(q, StringComparison.Ordinal))) return 1;
        return n.Contains(q, StringComparison.Ordinal) ? 2 : 3;
    }

    private void OnProgram(ProgramRow row, string? command)
    {
        MainWindow.Instance.Navigate("programs");
        var view = _programs();
        view.Reveal(row);
        if (command is not null) view.RunCommand(command);
    }

    // Secondary text is dimmed with opacity, except in a contrast theme, where text keeps the system colour.
    private static readonly double Dim = new Windows.UI.ViewManagement.AccessibilitySettings().HighContrast ? 1.0 : 0.7;

    private static FrameworkElement Render(Entry e)
    {
        if (e.Run is null)
        {
            // Group header or footer: not a command.
            var header = new TextBlock
            {
                Text = e.Title, FontSize = e.Group.Length > 0 ? 11 : 12, CharacterSpacing = e.Group.Length > 0 ? 50 : 0,
                FontWeight = e.Group.Length > 0 ? FontWeights.SemiBold : FontWeights.Normal,
                Opacity = Dim, Margin = new Thickness(0, 4, 0, 0), Tag = e, IsHitTestVisible = false,
            };
            return header;
        }

        var grid = new Grid { ColumnSpacing = 12, Tag = e, MinHeight = 36 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition());
        AutomationProperties.SetName(grid, e.Title);

        FrameworkElement icon;
        if (e.Tile is not null)
            icon = new Border
            {
                Width = 24, Height = 24, CornerRadius = new CornerRadius(5), Background = e.Tile, VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock
                {
                    Text = e.Initial, FontSize = 12, FontWeight = FontWeights.SemiBold, Foreground = new SolidColorBrush(Microsoft.UI.Colors.White),
                    HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center,
                },
            };
        else
            icon = new FontIcon { Glyph = e.Glyph ?? "", FontSize = 16, Width = 24, VerticalAlignment = VerticalAlignment.Center };
        grid.Children.Add(icon);

        var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
        text.Children.Add(new TextBlock { Text = e.Title, TextTrimming = TextTrimming.CharacterEllipsis });
        if (e.Sub.Length > 0)
            text.Children.Add(new TextBlock { Text = e.Sub, FontSize = 12, Opacity = Dim, TextTrimming = TextTrimming.CharacterEllipsis });
        Grid.SetColumn(text, 1);
        grid.Children.Add(text);
        return grid;
    }
}
