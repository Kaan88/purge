using System.ComponentModel;
using System.Globalization;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>
/// One row of the S1 program list, precomputed so the row template only reads strings. The first frame binds only
/// the tile, the two-line name and the size; <see cref="Extras"/> turns on after the first Rendering tick and loads
/// the deferred parts (size bar, expected leftovers, install date, icon). Patches, sizes, icons and details arrive
/// later still and update the row in place.
/// </summary>
public sealed partial class ProgramRow : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    public ProgramRow(InventoryEntry entry, long? sizeBytes, DateTime today)
    {
        Entry = entry;
        Name = entry.DisplayName;
        Version = entry.Version ?? "";
        Publisher = entry.Publisher ?? "";
        _sizeBytes = sizeBytes;
        _sizeText = sizeBytes is { } b ? FormatSize(b) : "";
        Installed = ProgramRules.InstallDate(entry);
        InstalledText = Installed?.ToString("d MMM yyyy", CultureInfo.CurrentCulture) ?? "";
        Initial = Name.Length > 0 && char.IsLetterOrDigit(Name[0]) ? char.ToUpperInvariant(Name[0]).ToString() : "?";
        _today = today;
        Classify();
    }

    private readonly DateTime _today;

    // Placeholder tiles until an icon arrives: a colour per publisher, the first letter.
    private static readonly Windows.UI.Color[] TileColors =
    [
        Rgb(0x0F, 0x6C, 0xBD), Rgb(0x87, 0x64, 0xB8), Rgb(0xC2, 0x39, 0xB3), Rgb(0xCA, 0x50, 0x10),
        Rgb(0x49, 0x82, 0x05), Rgb(0x03, 0x83, 0x87), Rgb(0x98, 0x6F, 0x0B), Rgb(0x4F, 0x6B, 0xED),
        Rgb(0x3B, 0x3B, 0x3B), Rgb(0xC4, 0x31, 0x4B),
    ];

    /// <summary>The placeholder tile colour for a publisher (or name), stable across runs.</summary>
    public static Brush TileFor(string key) => new SolidColorBrush(TileColors[(int)(StableHash(key) % (uint)TileColors.Length)]);

    private static Windows.UI.Color Rgb(byte r, byte g, byte b) => Windows.UI.Color.FromArgb(255, r, g, b);

    private static uint StableHash(string s)
    {
        var h = 2166136261u;
        foreach (var c in s) h = (h ^ c) * 16777619u;
        return h;
    }

    /// <summary>The entry as the engine described it so far; patches and details replace it.</summary>
    public InventoryEntry Entry { get; private set; }
    public string Name { get; }
    public string Version { get; }
    public string Publisher { get; }
    public DateTime? Installed { get; }
    public string InstalledText { get; }
    public string Initial { get; }
    public string NewTag { get; private set; } = "";

    private Brush? _tile;
    /// <summary>The placeholder tile; made when a row is first shown, not for every row of the list.</summary>
    public Brush TileBrush => _tile ??= TileFor(Publisher.Length > 0 ? Publisher : Name);

    public bool IsChild { get; private set; }
    public Microsoft.UI.Xaml.Thickness Indent { get; private set; }

    /// <summary>Second line of the name cell: publisher and installer kind.</summary>
    public string SubLine { get; private set; } = "";

    public bool IsApp { get; private set; }
    public bool IsComponent { get; private set; }
    public bool IsUnnamed { get; private set; }
    public bool IsRecent { get; private set; }

    /// <summary>Sorts and classifies the row again from <see cref="Entry"/> (after a patch).</summary>
    private void Classify()
    {
        var c = ProgramRules.Classify(Entry, Installed, _today);
        IsChild = c.IsChild;
        IsApp = c.IsApp;
        IsComponent = c.IsComponent;
        IsUnnamed = c.IsUnnamed;
        IsRecent = c.IsRecent;
        Indent = IsChild ? new Microsoft.UI.Xaml.Thickness(28, 0, 0, 0) : new Microsoft.UI.Xaml.Thickness(0);
        NewTag = Installed is { } n && (_today - n).TotalDays <= 3 ? "  new" : "";
        SubLine = Publisher.Length > 0 ? $"{Publisher} · {KindChip}" : KindChip;
    }

    /// <summary>The full name cell for its tooltip: names are trimmed in the list, and look-alike rows differ here.</summary>
    public string FullText => Join(" ", Name, Version) + "\n" + Join(" · ", SubLine, BitsText, "for " + ScopeText);

    private static string Join(string separator, params string?[] parts) =>
        string.Join(separator, parts.Where(p => !string.IsNullOrEmpty(p)));

    /// <summary>The list's column widths, shared by every row (they follow the list's width).</summary>
    public ProgramColumns Columns => ProgramColumns.Shared;

    /// <summary>What a screen reader says for the row (the list item's name): the program, not the type.</summary>
    public override string ToString() =>
        Name + (NewTag.Length > 0 ? ", new" : "") + (SubLine.Length > 0 ? ", " + SubLine : "");

    /// <summary>Takes what <c>programs.patch</c> or a later reading says about the program.</summary>
    public void Update(InventoryEntry entry)
    {
        Entry = entry;
        Classify();
    }

    private long? _sizeBytes;
    private string _sizeText;

    /// <summary>Measured size on disk; null until <c>size.ready</c> has it.</summary>
    public long? SizeBytes => _sizeBytes;

    public string SizeText => _sizeText;

    /// <summary>Takes a measured size (null: could not be measured).</summary>
    public void SetSize(long? bytes)
    {
        _sizeBytes = bytes;
        _sizeText = bytes is { } b ? FormatSize(b) : "";
        Raise(nameof(SizeText));
    }

    private bool _extras;
    /// <summary>True once the first frame is out: loads the deferred parts of the row.</summary>
    public bool Extras
    {
        get => _extras;
        set { if (_extras != value) { _extras = value; Raise(nameof(Extras)); RaiseVerdict(); } }
    }

    private double _barWidth;
    /// <summary>Width of the size bar in px (0 to 96), relative to the largest program in the list.</summary>
    public double BarWidth
    {
        get => _barWidth;
        set { if (_barWidth != value) { _barWidth = value; Raise(nameof(BarWidth)); } }
    }

    private ImageSource? _icon;
    /// <summary>The program's icon; null shows the placeholder tile.</summary>
    public ImageSource? Icon => _icon;

    /// <summary>Whether an icon replaced the placeholder tile (creates the row's image on demand).</summary>
    public bool HasIcon => _icon is not null;

    /// <summary>The image of an atlas or engine icon.</summary>
    public static ImageSource ToImage(AtlasIcon icon)
    {
        var bitmap = new WriteableBitmap(icon.Px, icon.Px);
        using (var stream = System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions.AsStream(bitmap.PixelBuffer))
            stream.Write(IconLoader.Premultiply(icon.Bgra));
        bitmap.Invalidate();
        return bitmap;
    }

    /// <summary>Shows an icon instead of the placeholder tile.</summary>
    public void SetIcon(ImageSource image)
    {
        _icon = image;
        Raise(nameof(Icon));
        Raise(nameof(HasIcon));
    }

    /// <summary>True once <c>programs.get</c> was asked for this row.</summary>
    public bool DetailsRequested { get; set; }

    /// <summary>True once the details of <c>programs.get</c> are in <see cref="Entry"/> (or the entry already had them).</summary>
    public bool DetailsLoaded { get; set; }

    private LeftoverForecast? _forecast;
    /// <summary>Expected leftovers; null until the engine has answered (shown as "Not known yet").</summary>
    public LeftoverForecast? Forecast
    {
        get => _forecast;
        set { _forecast = value; RaiseVerdict(); }
    }

    public ForecastVerdict Verdict => _forecast?.Verdict ?? ForecastVerdict.Unknown;
    public bool ShowClean => _extras && Verdict == ForecastVerdict.Clean;
    public bool ShowSome => _extras && Verdict == ForecastVerdict.Some;
    public bool ShowLarge => _extras && Verdict == ForecastVerdict.Large;
    public bool ShowUnknown => _extras && Verdict == ForecastVerdict.Unknown;

    /// <summary>The Leftovers cell text after its glyph: "Clean", "~1.2 GB cache", "Not known yet".</summary>
    public string LeftoverText => Verdict switch
    {
        ForecastVerdict.Clean => "Clean",
        ForecastVerdict.Unknown => "Not known yet",
        _ => (_forecast!.EstimateBytes is { } b ? "~" + FormatSize(b) : "Some") + (_forecast.What is { } w ? " " + w : ""),
    };

    /// <summary>For sorting by "likely junk": large first, unknown in the middle, clean last.</summary>
    public long JunkRank => Verdict switch
    {
        ForecastVerdict.Large or ForecastVerdict.Some => 1_000_000_000_000 + (_forecast!.EstimateBytes ?? 0),
        ForecastVerdict.Unknown => 0,
        _ => -1,
    };

    private void RaiseVerdict()
    {
        Raise(nameof(ShowClean)); Raise(nameof(ShowSome)); Raise(nameof(ShowLarge)); Raise(nameof(ShowUnknown));
        Raise(nameof(LeftoverText));
    }

    private void Raise(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    public bool InTab(ProgramTab tab) => ProgramRules.Classify(Entry, Installed, _today).InTab(tab);

    public bool Matches(string query) => ProgramRules.Matches(Entry, query);

    public string KindChip => Entry.Appx ? "Store app" : Entry.InstallerKind switch
    {
        InstallerKind.Msi => "MSI",
        InstallerKind.Inno => "Inno",
        InstallerKind.Nsis => "NSIS",
        InstallerKind.Burn => "Burn",
        _ => "Other",
    };

    public string KindText => Entry.Appx ? "Store app" : Entry.InstallerKind switch
    {
        InstallerKind.Msi => "MSI",
        InstallerKind.Inno => "Inno Setup",
        InstallerKind.Nsis => "NSIS",
        InstallerKind.Burn => "WiX Burn",
        _ => "Other installer",
    };

    public string BitsText => Entry.View == RegistryView.K32 ? "32-bit" : "64-bit";
    public string ScopeText => Entry.Scope == InstallScope.User ? "this user" : "all users";

    public static string FormatSize(long bytes) => ProgramRules.FormatSize(bytes);
}

/// <summary>
/// The widths of the program list's optional columns, one instance for all rows: when the list gets narrow, Installed,
/// then Expected leftovers, then Size go to zero (<see cref="ProgramRules.FitColumns"/>); Name always stays.
/// </summary>
public sealed partial class ProgramColumns : System.ComponentModel.INotifyPropertyChanged
{
    public static ProgramColumns Shared { get; } = new();

    public event System.ComponentModel.PropertyChangedEventHandler? PropertyChanged;

    public Microsoft.UI.Xaml.GridLength SizeWidth { get; private set; } = new(100);
    public Microsoft.UI.Xaml.GridLength LeftoversWidth { get; private set; } = new(150);
    public Microsoft.UI.Xaml.GridLength InstalledWidth { get; private set; } = new(92);

    /// <summary>What fits now.</summary>
    public ProgramRules.ListColumns Fit { get; private set; } = new(true, true, true);

    /// <summary>Takes the list's width; true when a column came or went.</summary>
    public bool Apply(double listWidth)
    {
        var fit = ProgramRules.FitColumns(listWidth);
        if (fit == Fit) return false;
        Fit = fit;
        SizeWidth = new(fit.Size ? 100 : 0);
        LeftoversWidth = new(fit.Leftovers ? 150 : 0);
        InstalledWidth = new(fit.Installed ? 92 : 0);
        foreach (var name in new[] { nameof(SizeWidth), nameof(LeftoversWidth), nameof(InstalledWidth), nameof(Fit) })
            PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(name));
        return true;
    }
}
