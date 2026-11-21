using System.ComponentModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace Purge.App.Views;

public enum Band { Safe, Likely, Weak, Protected }

public enum LeftoverKind { File, Registry, Task }

/// <summary>One line of evidence in the "why" card. ● explicit, ◐ corroborating, ○ note, ⚠ warning.</summary>
public sealed partial class EvidenceLine(string glyph, Brush glyphBrush, string text)
{
    public string Glyph { get; } = glyph;
    public Brush GlyphBrush { get; } = glyphBrush;
    public string Text { get; } = text;
}

/// <summary>
/// A row of the flattened S3 list (§9.4: a virtualized ListView with group header rows, not a TreeView): either a
/// group header or a candidate. Sample-only today; in M3 it wraps a <c>scan.candidates</c> entry.
/// </summary>
public sealed partial class LeftoverRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    // Group header
    private LeftoverRow(string group)
    {
        IsGroup = true;
        GroupName = group;
        Path = "";
        Why = "";
    }

    // Candidate
    public LeftoverRow(string group, string path, string why, Band band, string size = "", long bytes = 0, LeftoverKind kind = LeftoverKind.File)
    {
        GroupName = group;
        Path = path;
        Why = why;
        Band = band;
        SizeText = size;
        SizeBytes = bytes;
        Kind = kind;
        _checked = band == Band.Safe;
    }

    public static LeftoverRow Header(string group) => new(group);

    public static LeftoverRow Item(string group, string path, string why, Band band, string size = "", long bytes = 0,
        LeftoverKind kind = LeftoverKind.File) => new(group, path, why, band, size, bytes, kind);

    public bool IsGroup { get; }
    public string GroupName { get; }
    public string Path { get; }
    public string Why { get; }
    public Band Band { get; }
    public string SizeText { get; } = "";
    public long SizeBytes { get; }
    public LeftoverKind Kind { get; }
    /// <summary>The engine's candidate id (empty for sample rows).</summary>
    public string Id { get; init; } = "";
    public bool IsUserData { get; init; }
    public string Contents { get; init; } = "";
    public string FoundBy { get; init; } = "";
    // A List, not IReadOnlyList: a collection expression assigned to IReadOnlyList becomes a compiler-made type that
    // CsWinRT can't pass to ItemsSource ("Value does not fall within the expected range").
    public List<EvidenceLine>? Evidence { get; init; }

    public bool Selectable => !IsGroup && Band != Band.Protected;

    private bool _checked;
    public bool Checked
    {
        get => _checked;
        set { if (_checked != value) { _checked = value; Raise(nameof(Checked)); } }
    }

    // Group header state
    private bool? _groupChecked;
    public bool? GroupChecked
    {
        get => _groupChecked;
        set { if (_groupChecked != value) { _groupChecked = value; Raise(nameof(GroupChecked)); } }
    }

    private string _countText = "";
    public string CountText
    {
        get => _countText;
        set { if (_countText != value) { _countText = value; Raise(nameof(CountText)); } }
    }

    private string _groupSizeText = "";
    public string GroupSizeText
    {
        get => _groupSizeText;
        set { if (_groupSizeText != value) { _groupSizeText = value; Raise(nameof(GroupSizeText)); } }
    }

    private double _groupBarWidth;
    /// <summary>Width (0–120) of the group's bar: the share of its items that are selected.</summary>
    public double GroupBarWidth
    {
        get => _groupBarWidth;
        set { if (_groupBarWidth != value) { _groupBarWidth = value; Raise(nameof(GroupBarWidth)); } }
    }

    private string _groupBarTip = "";
    public string GroupBarTip
    {
        get => _groupBarTip;
        set { if (_groupBarTip != value) { _groupBarTip = value; Raise(nameof(GroupBarTip)); } }
    }

    private bool _expanded = true;
    public bool Expanded
    {
        get => _expanded;
        set { if (_expanded != value) { _expanded = value; Raise(nameof(Chevron)); } }
    }

    public string Chevron => _expanded ? "" : "";

    public Visibility GroupVisibility => IsGroup ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ItemVisibility => IsGroup ? Visibility.Collapsed : Visibility.Visible;
    public Visibility CheckVisibility => Selectable ? Visibility.Visible : Visibility.Collapsed;
    public Visibility LockVisibility => !IsGroup && Band == Band.Protected ? Visibility.Visible : Visibility.Collapsed;
    public Visibility SafeVisibility => !IsGroup && Band == Band.Safe ? Visibility.Visible : Visibility.Collapsed;
    public Visibility LikelyVisibility => !IsGroup && Band == Band.Likely ? Visibility.Visible : Visibility.Collapsed;
    public Visibility WeakVisibility => !IsGroup && Band == Band.Weak ? Visibility.Visible : Visibility.Collapsed;
    public Visibility ProtectedVisibility => LockVisibility;
    public double PathOpacity => Band == Band.Protected ? 0.6 : 1.0;

    private void Raise(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
