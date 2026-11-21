using System.ComponentModel;
using System.Globalization;
using Microsoft.UI.Xaml.Media;
using Purge.Client.Model;

namespace Purge.App.Views;

/// <summary>Which S1 tab an entry belongs to (§9.4). Grouping is UI policy; the engine never hides entries.</summary>
public enum ProgramTab { Apps, Components, Unnamed, Store, Recent }

/// <summary>
/// One row of the S1 program list, precomputed so the row template only reads strings. The first frame binds only
/// the tile, the two-line name and the size; <see cref="Extras"/> turns on after the first Rendering tick and loads
/// the deferred parts (size bar, expected leftovers, install date). The forecast arrives later still.
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
        SizeBytes = sizeBytes;
        SizeText = sizeBytes is { } b ? FormatSize(b) : "";
        Installed = InstallDate(entry);
        InstalledText = Installed?.ToString("d MMM yyyy", CultureInfo.CurrentCulture) ?? "";
        Initial = Name.Length > 0 && char.IsLetterOrDigit(Name[0]) ? char.ToUpperInvariant(Name[0]).ToString() : "?";
        IsChild = entry.Flags.ParentKey is not null;
        Indent = IsChild ? new Microsoft.UI.Xaml.Thickness(28, 0, 0, 0) : new Microsoft.UI.Xaml.Thickness(0);

        IsApp = entry.Flags.HasDisplayName && !entry.Flags.SystemComponent && !IsChild;
        IsComponent = entry.Flags.HasDisplayName && (entry.Flags.SystemComponent || IsChild);
        IsUnnamed = !entry.Flags.HasDisplayName;
        IsRecent = IsApp && Installed is { } d && (today - d).TotalDays <= 14;
        NewTag = Installed is { } n && (today - n).TotalDays <= 3 ? "new" : "";
        TileBrush = TileFor(Publisher.Length > 0 ? Publisher : Name);
        SubLine = Publisher.Length > 0 ? $"{Publisher} · {KindChip}" : KindChip;
    }

    // Placeholder tiles until real icons arrive (programs.icons): a colour per publisher, the first letter.
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

    public InventoryEntry Entry { get; }
    public string Name { get; }
    public string Version { get; }
    public string Publisher { get; }
    public long? SizeBytes { get; }
    public string SizeText { get; }
    public DateTime? Installed { get; }
    public string InstalledText { get; }
    public string Initial { get; }
    public string NewTag { get; }
    public Brush TileBrush { get; }
    public bool IsChild { get; }
    /// <summary>Second line of the name cell: publisher and installer kind.</summary>
    public string SubLine { get; }

    private bool _extras;
    /// <summary>True once the first frame is out: loads the deferred parts of the row.</summary>
    public bool Extras
    {
        get => _extras;
        set { if (_extras != value) { _extras = value; Raise(nameof(Extras)); RaiseVerdict(); } }
    }

    /// <summary>Width of the size bar in px (0–96), relative to the largest program in the list.</summary>
    public double BarWidth { get; set; }

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
    public Microsoft.UI.Xaml.Thickness Indent { get; }

    public bool IsApp { get; }
    public bool IsComponent { get; }
    public bool IsUnnamed { get; }
    public bool IsRecent { get; }

    public bool InTab(ProgramTab tab) => tab switch
    {
        ProgramTab.Apps => IsApp,
        ProgramTab.Components => IsComponent,
        ProgramTab.Unnamed => IsUnnamed,
        ProgramTab.Recent => IsRecent,
        _ => false,
    };

    public bool Matches(string query) =>
        query.Length == 0
        || Name.Contains(query, StringComparison.OrdinalIgnoreCase)
        || Publisher.Contains(query, StringComparison.OrdinalIgnoreCase)
        || Version.Contains(query, StringComparison.OrdinalIgnoreCase)
        || (Entry.InstallLocation?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false);

    public string KindChip => Entry.InstallerKind switch
    {
        InstallerKind.Msi => "MSI",
        InstallerKind.Inno => "Inno",
        InstallerKind.Nsis => "NSIS",
        InstallerKind.Burn => "Burn",
        _ => "Other",
    };

    public string KindText => Entry.InstallerKind switch
    {
        InstallerKind.Msi => "MSI",
        InstallerKind.Inno => "Inno Setup",
        InstallerKind.Nsis => "NSIS",
        InstallerKind.Burn => "WiX Burn",
        _ => "Other installer",
    };

    public string BitsText => Entry.View == RegistryView.K32 ? "32-bit" : "64-bit";
    public string ScopeText => Entry.Scope == InstallScope.User ? "this user" : "all users";

    /// <summary>Picks the install date: ARP or MSI date first, then the key's last write.</summary>
    private static DateTime? InstallDate(InventoryEntry e)
    {
        if (e.InstallTimeEvidence is not { Count: > 0 } ev) return null;
        InstallTimeEvidence? pick = null;
        foreach (var h in ev)
        {
            if (h.Source is InstallTimeSource.ArpInstallDate or InstallTimeSource.MsiInstallDate) { pick = h; break; }
            pick ??= h;
        }
        return pick is null ? null : DateTime.FromFileTimeUtc((long)pick.Time).ToLocalTime().Date;
    }

    public static string FormatSize(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double v = bytes;
        var u = 0;
        while (v >= 1024 && u < units.Length - 1) { v /= 1024; u++; }
        var fmt = v >= 100 || u == 0 ? "F0" : "F1";
        return v.ToString(fmt, CultureInfo.CurrentCulture) + " " + units[u];
    }
}
