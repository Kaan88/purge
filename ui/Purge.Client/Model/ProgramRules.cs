using System.Globalization;

namespace Purge.Client.Model;

/// <summary>The tabs of the Programs page. Grouping is UI policy; the engine never hides entries.</summary>
public enum ProgramTab { Apps, Components, Unnamed, Recent }

/// <summary>Where an entry belongs on the Programs page.</summary>
public readonly record struct ProgramClass(bool IsApp, bool IsComponent, bool IsUnnamed, bool IsRecent, bool IsChild)
{
    public bool InTab(ProgramTab tab) => tab switch
    {
        ProgramTab.Apps => IsApp,
        ProgramTab.Components => IsComponent,
        ProgramTab.Unnamed => IsUnnamed,
        ProgramTab.Recent => IsRecent,
        _ => false,
    };
}

/// <summary>
/// The Programs page's list rules without any UI types: which tab an entry is in, search, the order with child rows
/// under their parent, install dates and sizes as text. The view and its tests share this.
/// </summary>
public static class ProgramRules
{
    /// <summary>Days an app counts as "Recent" after it was installed.</summary>
    public const int RecentDays = 14;

    /// <summary>
    /// The tab of an entry. Apps are named, not system components and not children; Components are named system
    /// components and child entries (updates, Burn children); Unnamed have no DisplayName; Recent is an app
    /// installed within <see cref="RecentDays"/> days. An AppX package is an app.
    /// </summary>
    public static ProgramClass Classify(InventoryEntry entry, DateTime? installed, DateTime today)
    {
        var child = entry.Flags.ParentKey is not null;
        var named = entry.Flags.HasDisplayName;
        var app = named && !entry.Flags.SystemComponent && !child;
        return new ProgramClass(
            IsApp: app,
            IsComponent: named && (entry.Flags.SystemComponent || child),
            IsUnnamed: !named,
            IsRecent: app && installed is { } d && (today - d).TotalDays <= RecentDays,
            IsChild: child);
    }

    /// <summary>Whether the search text occurs in the name, publisher, version or install folder (not case sensitive).</summary>
    public static bool Matches(InventoryEntry entry, string query) =>
        query.Length == 0
        || entry.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)
        || (entry.Publisher?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
        || (entry.Version?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
        || (entry.InstallLocation?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false);

    /// <summary>The last segment of an entry's key path: the name a child's <c>ParentKey</c> refers to.</summary>
    public static string KeyName(string keyPath) => keyPath[(keyPath.LastIndexOf('\\') + 1)..];

    /// <summary>
    /// Orders <paramref name="rows"/> by <paramref name="key"/>, with each child row directly under its parent.
    /// A child whose parent is not among <paramref name="rows"/> (another tab, or filtered out) is ordered like any
    /// other row, so it is never lost. A key name can repeat on a real machine (the same key under the 32- and the
    /// 64-bit view, or HKLM and HKCU), so a child follows every row of that name.
    /// </summary>
    public static IEnumerable<T> Order<T, TKey>(IEnumerable<T> rows, Func<T, InventoryEntry> entry, Func<T, TKey> key, bool descending)
    {
        var list = rows.ToList();
        var byKey = list.Select(r => KeyName(entry(r).KeyPath)).ToHashSet(StringComparer.Ordinal);
        var parents = list.Where(r => entry(r).Flags.ParentKey is not { } p || !byKey.Contains(p));
        var ordered = descending ? parents.OrderByDescending(key) : parents.OrderBy(key);
        var children = list.Where(r => entry(r).Flags.ParentKey is { } p && byKey.Contains(p)).ToList();
        foreach (var parent in ordered)
        {
            yield return parent;
            var name = KeyName(entry(parent).KeyPath);
            foreach (var child in children)
                if (entry(child).Flags.ParentKey == name) yield return child;
        }
    }

    /// <summary>The install date: the ARP or MSI date first, then another hint, as a local date.</summary>
    public static DateTime? InstallDate(InventoryEntry entry)
    {
        if (entry.InstallTimeEvidence is not { Count: > 0 } evidence) return null;
        InstallTimeEvidence? pick = null;
        foreach (var hint in evidence)
        {
            if (hint.Source is InstallTimeSource.ArpInstallDate or InstallTimeSource.MsiInstallDate) { pick = hint; break; }
            pick ??= hint;
        }
        // A FILETIME outside the range of DateTime is a damaged value: no date.
        if (pick is null || pick.Time > (ulong)DateTime.MaxValue.ToFileTimeUtc()) return null;
        return DateTime.FromFileTimeUtc((long)pick.Time).ToLocalTime().Date;
    }

    /// <summary>"1.4 GB", "312 MB", "0 B".</summary>
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
